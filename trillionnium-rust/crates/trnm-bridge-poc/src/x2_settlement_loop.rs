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

const MAX_COMPENSATION_REASON_CHARS: usize = 160;

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
        let degraded_reason =
            normalize_compensation_reason(&heartbeat.message, "unknown heartbeat degradation");
        let reason = format!("heartbeat degraded: {degraded_reason}");
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
            let confirm_reason = normalize_compensation_reason(&reason, "unknown confirm failure");
            let reason = format!("settlement confirm failed: {confirm_reason}");
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

fn normalize_compensation_reason(reason: &str, fallback: &'static str) -> String {
    let sanitized: String = reason
        .chars()
        .map(|ch| {
            if ch.is_control()
                || matches!(
                    ch,
                    '\u{061C}'
                        | '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{200E}'
                        | '\u{200F}'
                        | '\u{FEFF}'
                        | '\u{2060}'
                        | '\u{202A}'
                        | '\u{202B}'
                        | '\u{202C}'
                        | '\u{202D}'
                        | '\u{202E}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{2066}'
                        | '\u{2067}'
                        | '\u{2068}'
                        | '\u{2069}'
                )
            {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");

    if collapsed.is_empty() {
        return fallback.to_string();
    }

    let mut normalized = String::new();
    for (idx, ch) in collapsed.chars().enumerate() {
        if idx >= MAX_COMPENSATION_REASON_CHARS {
            normalized.push('…');
            break;
        }
        normalized.push(ch);
    }
    normalized
}

pub fn current_status(request: &SettlementRequest) -> &BridgeStatus {
    &request.status
}
