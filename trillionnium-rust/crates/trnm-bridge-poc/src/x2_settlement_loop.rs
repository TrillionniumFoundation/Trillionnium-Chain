use crate::bridge_status::{BridgeStatus, CapabilityToken, SettlementError, SettlementRequest};
use crate::relay_heartbeat::HeartbeatOutcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementConfirm {
    Confirmed { height: u64 },
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementEvent {
    pub phase: &'static str,
    pub heartbeat_source_height: Option<u64>,
    pub heartbeat_target_height: Option<u64>,
    pub heartbeat_latency_ms: Option<u64>,
    pub confirm_height: Option<u64>,
    pub confirm_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementStep {
    Finalized { height: u64, event: SettlementEvent },
    Compensated { reason: String, event: SettlementEvent },
}

pub fn drive_minimal_settlement(
    request: &mut SettlementRequest,
    token: &CapabilityToken,
    heartbeat: &HeartbeatOutcome,
    confirm: SettlementConfirm,
) -> Result<SettlementStep, SettlementError> {
    let (hb_src, hb_tgt, hb_latency) = heartbeat
        .heartbeat
        .map(|h| (Some(h.source_height), Some(h.target_height), Some(h.latency_ms)))
        .unwrap_or((None, None, None));

    if heartbeat.degraded {
        let reason = format!("heartbeat degraded: {}", heartbeat.message);
        request.revert_authorized(token, reason.clone())?;
        let event = SettlementEvent {
            phase: "relay_heartbeat_degraded",
            heartbeat_source_height: hb_src,
            heartbeat_target_height: hb_tgt,
            heartbeat_latency_ms: hb_latency,
            confirm_height: None,
            confirm_reason: Some(reason.clone()),
        };
        eprintln!(
            "[x2-settlement] phase={} hb_source_height={:?} hb_target_height={:?} hb_latency_ms={:?} confirm_height={:?} confirm_reason={:?}",
            event.phase,
            event.heartbeat_source_height,
            event.heartbeat_target_height,
            event.heartbeat_latency_ms,
            event.confirm_height,
            event.confirm_reason,
        );
        return Ok(SettlementStep::Compensated { reason, event });
    }

    match confirm {
        SettlementConfirm::Confirmed { height } => {
            request.settle_authorized(token, height)?;
            let event = SettlementEvent {
                phase: "settlement_confirmed",
                heartbeat_source_height: hb_src,
                heartbeat_target_height: hb_tgt,
                heartbeat_latency_ms: hb_latency,
                confirm_height: Some(height),
                confirm_reason: None,
            };
            eprintln!(
                "[x2-settlement] phase={} hb_source_height={:?} hb_target_height={:?} hb_latency_ms={:?} confirm_height={:?} confirm_reason={:?}",
                event.phase,
                event.heartbeat_source_height,
                event.heartbeat_target_height,
                event.heartbeat_latency_ms,
                event.confirm_height,
                event.confirm_reason,
            );
            Ok(SettlementStep::Finalized { height, event })
        }
        SettlementConfirm::Failed { reason } => {
            let reason = format!("settlement confirm failed: {reason}");
            request.revert_authorized(token, reason.clone())?;
            let event = SettlementEvent {
                phase: "settlement_confirm_failed",
                heartbeat_source_height: hb_src,
                heartbeat_target_height: hb_tgt,
                heartbeat_latency_ms: hb_latency,
                confirm_height: None,
                confirm_reason: Some(reason.clone()),
            };
            eprintln!(
                "[x2-settlement] phase={} hb_source_height={:?} hb_target_height={:?} hb_latency_ms={:?} confirm_height={:?} confirm_reason={:?}",
                event.phase,
                event.heartbeat_source_height,
                event.heartbeat_target_height,
                event.heartbeat_latency_ms,
                event.confirm_height,
                event.confirm_reason,
            );
            Ok(SettlementStep::Compensated { reason, event })
        }
    }
}

pub fn current_status(request: &SettlementRequest) -> &BridgeStatus {
    &request.status
}
