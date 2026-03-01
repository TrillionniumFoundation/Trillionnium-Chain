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
        let degraded_reason = normalize_compensation_reason(
            &heartbeat.message,
            "unknown heartbeat degradation",
        );
        let reason = format!("heartbeat degraded: {degraded_reason}");
        request.revert_authorized(token, reason.clone())?;
        return Ok(SettlementStep::Compensated { reason });
    }

    match confirm {
        SettlementConfirm::Confirmed { height } => {
            request.settle_authorized(token, height)?;
            Ok(SettlementStep::Finalized { height })
        }
        SettlementConfirm::Failed { reason } => {
            let confirm_reason =
                normalize_compensation_reason(&reason, "unknown confirm failure");
            let reason = format!("settlement confirm failed: {confirm_reason}");
            request.revert_authorized(token, reason.clone())?;
            Ok(SettlementStep::Compensated { reason })
        }
    }
}

fn normalize_compensation_reason(reason: &str, fallback: &'static str) -> String {
    let sanitized: String = reason
        .chars()
        .map(|ch| {
            if ch.is_control()
                || matches!(ch, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
            {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");

    if collapsed.is_empty() {
        fallback.to_string()
    } else {
        collapsed
    }
}

pub fn current_status(request: &SettlementRequest) -> &BridgeStatus {
    &request.status
}
