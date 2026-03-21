use crate::bridge_status::{BridgeStatus, CapabilityToken, SettlementError, SettlementRequest};
use crate::relay_heartbeat::HeartbeatOutcome;

fn expected_terminal_state(confirm: &SettlementConfirm, heartbeat: &HeartbeatOutcome) -> &'static str {
    if heartbeat.degraded || matches!(confirm, SettlementConfirm::Failed { .. }) {
        "reverted"
    } else {
        "finalized"
    }
}

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
    Finalized {
        height: u64,
        event: SettlementEvent,
    },
    Compensated {
        reason: String,
        event: SettlementEvent,
    },
}

const MAX_COMPENSATION_REASON_CHARS: usize = 160;

fn validate_heartbeat_outcome(heartbeat: &HeartbeatOutcome) -> Result<(), SettlementError> {
    let Some(metrics) = heartbeat.heartbeat else {
        return Ok(());
    };

    if metrics.source_height == 0 {
        return Err(SettlementError::InvalidHeight { height: 0 });
    }

    if metrics.target_height == 0 || metrics.target_height > metrics.source_height {
        return Err(SettlementError::InvalidHeight {
            height: metrics.target_height,
        });
    }

    Ok(())
}

fn heartbeat_metrics_for_event(heartbeat: &HeartbeatOutcome) -> (Option<u64>, Option<u64>, Option<u64>) {
    heartbeat
        .heartbeat
        .filter(|h| h.source_height > 0 && h.target_height > 0 && h.target_height <= h.source_height)
        .map(|h| {
            (
                Some(h.source_height),
                Some(h.target_height),
                Some(h.latency_ms),
            )
        })
        .unwrap_or((None, None, None))
}

pub fn drive_minimal_settlement(
    request: &mut SettlementRequest,
    token: &CapabilityToken,
    heartbeat: &HeartbeatOutcome,
    confirm: SettlementConfirm,
) -> Result<SettlementStep, SettlementError> {
    let expected_to = expected_terminal_state(&confirm, heartbeat);
    match current_status(request) {
        BridgeStatus::Pending => {}
        BridgeStatus::Finalized(_) => {
            return Err(SettlementError::InvalidTransition {
                from: "finalized",
                to: expected_to,
            });
        }
        BridgeStatus::Reverted(_) => {
            return Err(SettlementError::InvalidTransition {
                from: "reverted",
                to: expected_to,
            });
        }
    }

    if heartbeat.should_retry && !heartbeat.degraded {
        let reason = normalize_compensation_reason(&heartbeat.message, "heartbeat retry pending");
        return Err(SettlementError::HeartbeatRetryPending { reason });
    }

    validate_heartbeat_outcome(heartbeat)?;

    let (hb_src, hb_tgt, hb_latency) = heartbeat_metrics_for_event(heartbeat);

    if heartbeat.degraded {
        let degraded_reason =
            normalize_compensation_reason(&heartbeat.message, "unknown heartbeat failure");
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
            if height == 0 {
                return Err(SettlementError::InvalidHeight { height });
            }
            if let Some(target_height) = hb_tgt {
                if height < target_height {
                    return Err(SettlementError::InvalidHeight { height });
                }
            }
            if let Some(source_height) = hb_src {
                let max_confirm_height = source_height.saturating_add(1);
                if height > max_confirm_height {
                    return Err(SettlementError::InvalidHeight { height });
                }
            }
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

fn is_sanitized_to_space(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00A0}'
                | '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{1680}'
                | '\u{180E}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{2007}'
                | '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{202F}'
                | '\u{2000}'
                | '\u{2001}'
                | '\u{2002}'
                | '\u{2003}'
                | '\u{2004}'
                | '\u{2005}'
                | '\u{2006}'
                | '\u{2008}'
                | '\u{2009}'
                | '\u{200A}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2065}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{206A}'
                | '\u{206B}'
                | '\u{206C}'
                | '\u{206D}'
                | '\u{206E}'
                | '\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'
                | '\u{FFFA}'
                | '\u{FFFB}'
        )
        || ('\u{FE00}'..='\u{FE0F}').contains(&ch)
        || ('\u{E0100}'..='\u{E01EF}').contains(&ch)
}

fn normalize_compensation_reason(reason: &str, fallback: &'static str) -> String {
    let sanitized: String = reason
        .chars()
        .map(|ch| if is_sanitized_to_space(ch) { ' ' } else { ch })
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

#[cfg(test)]
mod tests {
    use super::{drive_minimal_settlement, normalize_compensation_reason, SettlementConfirm};
    use crate::bridge_status::{
        BridgeStatus, CapabilityToken, SettlementCapability, SettlementError, SettlementRequest,
    };
    use crate::relay_heartbeat::{HeartbeatOutcome, RelayHeartbeat};

    #[test]
    fn normalize_compensation_reason_strips_controls_and_invisibles() {
        let raw = "  timeout\u{202E}\n\t\u{200B} while\u{2066} settling  ";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "timeout while settling");
    }

    #[test]
    fn normalize_compensation_reason_enforces_max_len_with_ellipsis() {
        let raw = "a".repeat(220);
        let normalized = normalize_compensation_reason(&raw, "fallback");
        assert_eq!(normalized.chars().count(), 161);
        assert!(normalized.ends_with('…'));
    }

    #[test]
    fn normalize_compensation_reason_exact_cap_has_no_ellipsis() {
        let raw = "b".repeat(160);
        let normalized = normalize_compensation_reason(&raw, "fallback");
        assert_eq!(normalized.chars().count(), 160);
        assert_eq!(normalized, raw);
        assert!(!normalized.ends_with('…'));
    }

    #[test]
    fn normalize_compensation_reason_uses_fallback_when_empty_after_sanitize() {
        let raw = "\u{200B}\u{202E}\n\t\u{2066}";
        let normalized = normalize_compensation_reason(raw, "unknown confirm failure");
        assert_eq!(normalized, "unknown confirm failure");
    }

    #[test]
    fn normalize_compensation_reason_strips_invisible_math_operators_and_mvs() {
        let raw = "target\u{2061} relay\u{2062} timeout\u{2063} signal\u{2064}\u{180E}";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_collapses_crlf_and_unicode_separators_for_replay_stability() {
        let raw = "target\r\nrelay\u{2028}timeout\u{2029}signal\n";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_bidi_markers_for_replay_stability() {
        let raw = "target\u{200E} relay\u{200F} timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_soft_hyphen_for_replay_stability() {
        let raw = "target\u{00AD}relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_legacy_bidi_isolates_for_replay_stability() {
        let raw = "target\u{206A} relay\u{206B} timeout\u{206C} signal\u{206D}\u{206E}\u{206F}";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_variation_selectors_and_cgj_for_log_consensus() {
        let raw = "target\u{FE0F} relay\u{E0100} timeout\u{034F} signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_collapses_nbsp_family_for_replay_stability() {
        let raw = "target\u{00A0}relay\u{2007}timeout\u{202F}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_alm_and_zwnj_for_replay_stability() {
        let raw = "target\u{061C} relay\u{200C} timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_collapses_medium_math_and_ideographic_spaces() {
        let raw = "target\u{205F}relay\u{3000}timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_collapses_general_punctuation_spaces() {
        let raw = "target\u{2000}relay\u{2001}timeout\u{2002}signal\u{2003}confirm\u{2004}lag\u{2005}audit\u{2006}trail";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal confirm lag audit trail");
    }

    #[test]
    fn normalize_compensation_reason_collapses_thin_space_family_for_replay_stability() {
        let raw = "target\u{2008}relay\u{2009}timeout\u{200A}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_hangul_fillers_for_replay_stability() {
        let raw = "target\u{115F}relay\u{1160}timeout\u{3164}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
        let raw = "target\u{2065} relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_collapses_ogham_space_mark_for_replay_stability() {
        let raw = "target\u{1680}relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_interlinear_annotation_controls_for_replay_stability() {
        let raw = "target\u{FFF9}relay\u{FFFA}timeout\u{FFFB}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn drive_minimal_settlement_rejects_confirm_height_past_source_finality_window() {
        let mut request = SettlementRequest::new(1, "0xconfirm-height-jump".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 699,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: false,
            message: "heartbeat ok".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 702 },
        )
        .unwrap_err();

        assert_eq!(err, SettlementError::InvalidHeight { height: 702 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_rejects_degraded_heartbeat_with_invalid_progression_before_revert() {
        let mut request = SettlementRequest::new(1, "0xdegraded-invalid-heartbeat".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "relay heartbeat degraded".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .unwrap_err();

        assert_eq!(err, SettlementError::InvalidHeight { height: 701 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_retry_pending_heartbeat_with_invalid_progression_stays_retry_bounded() {
        let mut request = SettlementRequest::new(1, "0xretry-invalid-heartbeat".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: true,
            degraded: false,
            message: "relay heartbeat retry pending".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .unwrap_err();

        assert_eq!(
            err,
            SettlementError::HeartbeatRetryPending {
                reason: "relay heartbeat retry pending".to_string(),
            }
        );
        assert_eq!(request.status, BridgeStatus::Pending);
    }
}
