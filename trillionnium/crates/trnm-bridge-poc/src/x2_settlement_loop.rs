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

fn has_invalid_heartbeat_bounds(heartbeat: &HeartbeatOutcome) -> bool {
    heartbeat
        .heartbeat
        .map(|h| h.source_height == 0 || h.target_height == 0 || h.target_height > h.source_height)
        .unwrap_or(false)
}

fn invalid_heartbeat_embedded_height(heartbeat: &HeartbeatOutcome) -> u64 {
    heartbeat
        .heartbeat
        .map(|h| h.source_height.max(h.target_height))
        .unwrap_or(0)
}

fn degraded_reason_matches_prefix(normalized: &str, expected: &str) -> bool {
    normalized.eq_ignore_ascii_case(expected)
        || normalized
            .get(..expected.len())
            .map(|prefix| prefix.eq_ignore_ascii_case(expected))
            .unwrap_or(false)
            && normalized[expected.len()..]
                .chars()
                .next()
                .map(|ch| {
                    matches!(
                        ch,
                        ':' | '：' | ';' | '；' | ',' | '，' | '、' | '.' | '．' | '。' | '(' | ')' | '[' | ']' | '{' | '}'
                            | '（' | '）' | '［' | '］' | '｛' | '｝' | '<' | '＜' | ' ' | '-' | '–' | '—' | '－'
                    )
                })
                .unwrap_or(false)
}

fn degraded_reason_allows_invalid_embedded_metrics(message: &str) -> bool {
    let normalized = normalize_compensation_reason(message, "");
    degraded_reason_matches_prefix(&normalized, "invalid heartbeat height")
        || degraded_reason_matches_prefix(&normalized, "invalid heartbeat progression")
}

fn emit_settlement_event(event: &SettlementEvent) {
    eprintln!(
        "[x2-settlement] phase={} hb_source_height={:?} hb_target_height={:?} hb_latency_ms={:?} confirm_height={:?} confirm_reason={:?}",
        event.phase,
        event.heartbeat_source_height,
        event.heartbeat_target_height,
        event.heartbeat_latency_ms,
        event.confirm_height,
        event.confirm_reason,
    );
}

/// Drives the minimal settlement state transition after relay liveness has been
/// sampled and a settlement confirmation result is available.
///
/// Layering contract:
/// - `relay_heartbeat` establishes whether the path is healthy enough to attempt
///   settlement at all and provides bounded source/target height evidence.
/// - this function consumes that evidence and performs the bridge-side terminal
///   transition only (`Pending -> Finalized` or `Pending -> Reverted`).
/// - replay protection is evaluated against the already-materialized bridge
///   state before any fresh confirmation detail is allowed to reinterpret a
///   terminal outcome.
/// - the finality boundary here is intentionally narrow: confirmation heights
///   may prove `source + 1` progress for settlement, but they do not upgrade or
///   downgrade oracle confidence on their own.
/// - oracle confidence, snapshot freshness, and RPC parsing remain outside this
///   function; callers must fail closed before entering here when oracle data is
///   insufficient or non-canonical.
///
/// The ordering is intentionally conservative: degraded or retry-pending
/// heartbeat outcomes block finalization before confirmation details can weaken
/// the fail-closed boundary.
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

    let (hb_src, hb_tgt, hb_latency) = heartbeat_metrics_for_event(heartbeat);

    if heartbeat.degraded {
        if has_invalid_heartbeat_bounds(heartbeat)
            && !degraded_reason_allows_invalid_embedded_metrics(&heartbeat.message)
        {
            return Err(SettlementError::InvalidHeight {
                height: invalid_heartbeat_embedded_height(heartbeat),
            });
        }

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
        emit_settlement_event(&event);
        return Ok(SettlementStep::Compensated { reason, event });
    }

    if heartbeat.should_retry && !matches!(confirm, SettlementConfirm::Failed { .. }) {
        return Err(SettlementError::HeartbeatRetryPending {
            reason: normalize_compensation_reason(
                &heartbeat.message,
                "heartbeat retry pending",
            ),
        });
    }

    if has_invalid_heartbeat_bounds(heartbeat) {
        let height = match &confirm {
            SettlementConfirm::Confirmed { height } => *height,
            SettlementConfirm::Failed { .. } => heartbeat
                .heartbeat
                .map(|h| h.target_height.max(h.source_height))
                .unwrap_or(0),
        };
        return Err(SettlementError::InvalidHeight { height });
    }

    match confirm {
        SettlementConfirm::Confirmed { height } => {
            if height == 0 {
                return Err(SettlementError::InvalidHeight { height });
            }
            if hb_src.is_none() || hb_tgt.is_none() {
                return Err(SettlementError::InvalidHeight { height });
            }
            if let Some(target_height) = hb_tgt {
                if height < target_height {
                    return Err(SettlementError::InvalidHeight { height });
                }
                if height == target_height && target_height != u64::MAX {
                    return Err(SettlementError::InvalidHeight { height });
                }
            }
            if let Some(source_height) = hb_src {
                let max_confirm_height = source_height.saturating_add(1);
                if height > max_confirm_height {
                    return Err(SettlementError::InvalidHeight { height });
                }
                // Once the target heartbeat has already caught up to the source head,
                // only the stronger source+1 settlement boundary remains acceptable.
                // Accepting the stale source-height confirmation would weaken the
                // observed finality overlay even though a stricter boundary is already
                // visible in the embedded heartbeat evidence.
                if hb_tgt == Some(source_height) && height != max_confirm_height {
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
            emit_settlement_event(&event);
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
            emit_settlement_event(&event);
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
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'
                | '\u{180C}'
                | '\u{180D}'
                | '\u{180E}'
                | '\u{180F}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FFA0}'
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
        || ('\u{1D173}'..='\u{1D17A}').contains(&ch)
        || ('\u{E0000}'..='\u{E007F}').contains(&ch)
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
    for ch in collapsed.chars() {
        if normalized.chars().count() >= MAX_COMPENSATION_REASON_CHARS {
            normalized.pop();
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
    use super::{
        degraded_reason_allows_invalid_embedded_metrics, drive_minimal_settlement,
        normalize_compensation_reason, SettlementConfirm, SettlementEvent, SettlementStep,
    };
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
    fn normalize_compensation_reason_enforces_bounded_max_len_with_ellipsis() {
        let raw = "a".repeat(220);
        let normalized = normalize_compensation_reason(&raw, "fallback");
        assert_eq!(normalized.chars().count(), 160);
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
    fn normalize_compensation_reason_strips_halfwidth_hangul_filler_for_replay_stability() {
        let raw = "target\u{FFA0}relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
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
    fn normalize_compensation_reason_strips_directional_isolates_for_replay_stability() {
        let raw = "target\u{2067} relay\u{2068} timeout\u{2069} signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
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
    fn normalize_compensation_reason_strips_plane1_musical_controls_for_log_consensus() {
        let raw = "target\u{1D173}relay\u{1D174}timeout\u{1D17A}signal";
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
    fn normalize_compensation_reason_strips_zwj_and_mongolian_fvs_for_replay_stability() {
        let raw = "target\u{200D}relay\u{180F}timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_mongolian_free_variation_selectors_for_replay_stability() {
        let raw = "target\u{180B}relay\u{180C}timeout\u{180D}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_collapses_medium_math_and_ideographic_spaces() {
        let raw = "target\u{205F}relay\u{3000}timeout";
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
    fn normalize_compensation_reason_strips_khmer_inherent_vowels_for_replay_stability() {
        let raw = "target\u{17B4}relay\u{17B5}timeout";
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
    fn normalize_compensation_reason_strips_braille_blank_for_replay_stability() {
        let raw = "target\u{2800}relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
        let raw = "target\u{2065} relay timeout";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_compensation_reason_strips_bom_word_joiner_and_variation_selectors_for_replay_stability() {
        let raw = "target\u{FEFF}relay\u{2060}timeout\u{FE0F}signal\u{E0100}";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_unicode_tag_controls_for_replay_stability() {
        let raw = "target\u{E0001}relay\u{E0020}timeout\u{E007F}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_compensation_reason_strips_interlinear_annotation_controls_for_replay_stability() {
        let raw = "target\u{FFF9}relay\u{FFFA}timeout\u{FFFB}signal";
        let normalized = normalize_compensation_reason(raw, "fallback");
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn degraded_reason_allows_invalid_embedded_metrics_for_english_punctuation_suffix() {
        assert!(degraded_reason_allows_invalid_embedded_metrics(
            "invalid heartbeat progression: target height exceeded source sample"
        ));
    }

    #[test]
    fn degraded_reason_allows_invalid_embedded_metrics_for_cjk_punctuation_suffix() {
        assert!(degraded_reason_allows_invalid_embedded_metrics(
            "invalid heartbeat height: source height is zero"
        ));
    }

    #[test]
    fn degraded_reason_allows_invalid_embedded_metrics_for_fullwidth_full_stop_suffix() {
        assert!(degraded_reason_allows_invalid_embedded_metrics(
            "invalid heartbeat progression．target height exceeded source sample"
        ));
    }

    #[test]
    fn degraded_reason_allows_invalid_embedded_metrics_for_em_dash_suffix() {
        assert!(degraded_reason_allows_invalid_embedded_metrics(
            "invalid heartbeat progression—target height exceeded source sample"
        ));
    }

    #[test]
    fn drive_minimal_settlement_emits_finalized_event_with_canonical_heartbeat_bounds() {
        let mut request = SettlementRequest::new(1, "0xsettlement-confirmed".to_string());
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

        let step = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 700 },
        )
        .expect("settlement should finalize inside finality window");

        match step {
            crate::x2_settlement_loop::SettlementStep::Finalized { height, event } => {
                assert_eq!(height, 700);
                assert_eq!(event.phase, "settlement_confirmed");
                assert_eq!(event.heartbeat_source_height, Some(700));
                assert_eq!(event.heartbeat_target_height, Some(699));
                assert_eq!(event.heartbeat_latency_ms, Some(19));
                assert_eq!(event.confirm_height, Some(700));
                assert_eq!(event.confirm_reason, None);
            }
            other => panic!("unexpected settlement step: {other:?}"),
        }

        assert_eq!(request.status, BridgeStatus::Finalized(700));
    }

    #[test]
    fn drive_minimal_settlement_compensates_failed_confirm_with_sanitized_reason() {
        let mut request = SettlementRequest::new(1, "0xsettlement-failed".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 699,
                latency_ms: 21,
            }),
            should_retry: false,
            degraded: false,
            message: "heartbeat ok".to_string(),
        };

        let step = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Failed {
                reason: " confirm\u{202E}\n timeout\u{200B} ".to_string(),
            },
        )
        .expect("failed confirm should compensate with normalized reason");

        match step {
            crate::x2_settlement_loop::SettlementStep::Compensated { reason, event } => {
                assert_eq!(reason, "settlement confirm failed: confirm timeout");
                assert_eq!(event.phase, "settlement_confirm_failed");
                assert_eq!(event.heartbeat_source_height, Some(700));
                assert_eq!(event.heartbeat_target_height, Some(699));
                assert_eq!(event.heartbeat_latency_ms, Some(21));
                assert_eq!(event.confirm_height, None);
                assert_eq!(
                    event.confirm_reason.as_deref(),
                    Some("settlement confirm failed: confirm timeout")
                );
            }
            other => panic!("unexpected settlement step: {other:?}"),
        }

        assert_eq!(
            request.status,
            BridgeStatus::Reverted("settlement confirm failed: confirm timeout".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_rejects_confirm_height_exactly_at_target_floor() {
        let mut request = SettlementRequest::new(1, "0xconfirm-height-floor".to_string());
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
            SettlementConfirm::Confirmed { height: 699 },
        )
        .expect_err("settlement must fail closed at the heartbeat target floor");

        assert_eq!(err, SettlementError::InvalidHeight { height: 699 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_accepts_confirm_height_exactly_at_source_finality_ceiling() {
        let mut request = SettlementRequest::new(1, "0xconfirm-height-ceiling".to_string());
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

        let step = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("settlement should finalize at source finality ceiling");

        match step {
            crate::x2_settlement_loop::SettlementStep::Finalized { height, event } => {
                assert_eq!(height, 701);
                assert_eq!(event.phase, "settlement_confirmed");
                assert_eq!(event.heartbeat_source_height, Some(700));
                assert_eq!(event.heartbeat_target_height, Some(699));
                assert_eq!(event.confirm_height, Some(701));
                assert_eq!(event.confirm_reason, None);
            }
            other => panic!("unexpected settlement step: {other:?}"),
        }

        assert_eq!(request.status, BridgeStatus::Finalized(701));
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
    fn drive_minimal_settlement_rejects_confirm_height_equal_to_target_overlay_boundary() {
        let mut request = SettlementRequest::new(1, "0xconfirm-target-boundary".to_string());
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
            SettlementConfirm::Confirmed { height: 699 },
        )
        .expect_err("confirm height must advance beyond observed target finality boundary");

        assert_eq!(err, SettlementError::InvalidHeight { height: 699 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_accepts_exact_source_plus_one_confirm_height_at_finality_boundary() {
        let mut request = SettlementRequest::new(1, "0xconfirm-finality-boundary".to_string());
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

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("exact source+1 finality boundary should remain confirmable");

        assert_eq!(request.status, BridgeStatus::Finalized(701));
        assert_eq!(
            out,
            SettlementStep::Finalized {
                height: 701,
                event: SettlementEvent {
                    phase: "settlement_confirmed",
                    heartbeat_source_height: Some(700),
                    heartbeat_target_height: Some(699),
                    heartbeat_latency_ms: Some(19),
                    confirm_height: Some(701),
                    confirm_reason: None,
                },
            }
        );
    }

    #[test]
    fn drive_minimal_settlement_accepts_exact_source_plus_one_confirm_height_when_target_has_reached_source_head() {
        let mut request = SettlementRequest::new(1, "0xconfirm-head-plus-one-boundary".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 700,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: false,
            message: "heartbeat ok".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("source+1 overlay boundary should remain confirmable even when target has reached source head");

        assert_eq!(request.status, BridgeStatus::Finalized(701));
        assert_eq!(
            out,
            SettlementStep::Finalized {
                height: 701,
                event: SettlementEvent {
                    phase: "settlement_confirmed",
                    heartbeat_source_height: Some(700),
                    heartbeat_target_height: Some(700),
                    heartbeat_latency_ms: Some(19),
                    confirm_height: Some(701),
                    confirm_reason: None,
                },
            }
        );
    }

    #[test]
    fn drive_minimal_settlement_rejects_stale_source_height_when_target_has_reached_source_head() {
        let mut request = SettlementRequest::new(1, "0xconfirm-head-stale-boundary".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 700,
                target_height: 700,
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
            SettlementConfirm::Confirmed { height: 700 },
        )
        .expect_err("stale source-height confirmation must fail closed once target has reached source head");

        assert_eq!(err, SettlementError::InvalidHeight { height: 700 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_accepts_exact_u64_max_confirm_height_at_saturated_finality_boundary() {
        let mut request = SettlementRequest::new(1, "0xconfirm-max-boundary".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: u64::MAX,
                target_height: u64::MAX,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: false,
            message: "heartbeat ok".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: u64::MAX },
        )
        .expect("exact saturated finality boundary should remain confirmable");

        assert_eq!(request.status, BridgeStatus::Finalized(u64::MAX));
        assert_eq!(
            out,
            SettlementStep::Finalized {
                height: u64::MAX,
                event: SettlementEvent {
                    phase: "settlement_confirmed",
                    heartbeat_source_height: Some(u64::MAX),
                    heartbeat_target_height: Some(u64::MAX),
                    heartbeat_latency_ms: Some(19),
                    confirm_height: Some(u64::MAX),
                    confirm_reason: None,
                },
            }
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_prefers_compensation() {
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
            message: "invalid heartbeat progression".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .unwrap();

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat progression".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_sanitized_invalid_progression_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-sanitized".to_string(),
        );
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
            message: "  invalid\u{200B} heartbeat\u{202E} progression\n".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("sanitized invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat progression".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression: target 701 > source 700".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression: target 701 > source 700"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression: target 701 > source 700"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression: target 701 > source 700"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_colon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-colon".to_string(),
        );
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
            message: "invalid heartbeat progression：target 701 > source 700".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth colon suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression：target 701 > source 700"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression：target 701 > source 700"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression：target 701 > source 700"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_hyphen_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-hyphen-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression - target 701 > source 700".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("hyphen-delimited diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression - target 701 > source 700"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression - target 701 > source 700"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression - target 701 > source 700"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_em_dash_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-em-dash-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression — target 701 > source 700".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("em-dash-delimited diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression — target 701 > source 700"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression — target 701 > source 700"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression — target 701 > source 700"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_hyphen_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-hyphen-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression－target 701 > source 700".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth hyphen-delimited diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression－target 701 > source 700"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression－target 701 > source 700"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression－target 701 > source 700"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-bracketed-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression [target=701 source=700]".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("bracketed diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression [target=701 source=700]"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression [target=701 source=700]"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression [target=701 source=700]"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-bracketed-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression（target=701 source=700）".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth bracketed diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression（target=701 source=700）"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression（target=701 source=700）"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression（target=701 source=700）"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_square_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-square-bracketed-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression［target=701 source=700］".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth square bracket diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression［target=701 source=700］"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression［target=701 source=700］"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression［target=701 source=700］"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_angle_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-angle-bracketed-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression<target=701 source=700>".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("angle bracket diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression<target=701 source=700>"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression<target=701 source=700>"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression<target=701 source=700>"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_angle_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-angle-bracketed-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression＜target=701 source=700＞".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth angle bracket diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression＜target=701 source=700＞"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression＜target=701 source=700＞"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression＜target=701 source=700＞"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_curly_braced_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-fullwidth-curly-braced-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression｛target=701 source=700｝".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth curly brace diagnostic suffix on invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression｛target=701 source=700｝"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression｛target=701 source=700｝"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression｛target=701 source=700｝"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_cannot_be_upgraded_by_valid_confirm_height() {
        let mut request = SettlementRequest::new(1, "0xdegraded-valid-confirm".to_string());
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
            degraded: true,
            message: "relay heartbeat degraded".to_string(),
        };

        let step = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 700 },
        )
        .expect("degraded heartbeat should fail closed before valid confirm height can finalize");

        match step {
            crate::x2_settlement_loop::SettlementStep::Compensated { reason, event } => {
                assert_eq!(reason, "heartbeat degraded: relay heartbeat degraded");
                assert_eq!(event.phase, "relay_heartbeat_degraded");
                assert_eq!(event.heartbeat_source_height, Some(700));
                assert_eq!(event.heartbeat_target_height, Some(699));
                assert_eq!(event.heartbeat_latency_ms, Some(19));
                assert_eq!(event.confirm_height, None);
                assert_eq!(
                    event.confirm_reason.as_deref(),
                    Some("heartbeat degraded: relay heartbeat degraded")
                );
            }
            other => panic!("unexpected settlement step: {other:?}"),
        }

        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: relay heartbeat degraded".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_mixed_case_invalid_progression_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-heartbeat-mixed-case".to_string(),
        );
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
            message: " Invalid Heartbeat Progression ".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("mixed-case invalid progression should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: Invalid Heartbeat Progression".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: Invalid Heartbeat Progression".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: Invalid Heartbeat Progression".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_sanitized_invalid_height_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-sanitized".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "  invalid\u{200B} heartbeat\u{202E} height\n".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("sanitized invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: invalid heartbeat height".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height: source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("diagnostic suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height: source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height: source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height: source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_colon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-colon".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height：source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth colon suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height：source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height：source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height：source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_comma_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-comma".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height，source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth comma suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height，source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height，source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height，source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_semicolon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-semicolon".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height；source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth semicolon suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height；source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height；source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height；source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_ascii_semicolon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-ascii-semicolon".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height; source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("ASCII semicolon suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height; source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height; source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height; source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_en_dash_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-en-dash".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height – source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("en-dash suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height – source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height – source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height – source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_period_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-period".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height. source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("period suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height. source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height. source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height. source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_em_dash_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-em-dash".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height — source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("em-dash suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height — source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height — source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height — source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_full_stop_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-full-stop".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height．source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth full stop suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height．source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height．source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height．source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_ideographic_full_stop_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-ideographic-full-stop".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height。source=0 target=701".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("ideographic full stop suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height。source=0 target=701"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height。source=0 target=701"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height。source=0 target=701".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-bracketed-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height [source=0 target=701]".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("bracketed diagnostic suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height [source=0 target=701]"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height [source=0 target=701]"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height [source=0 target=701]"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-bracketed-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height（source=0 target=701）".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth bracketed diagnostic suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height（source=0 target=701）"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height（source=0 target=701）"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height（source=0 target=701）"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_square_bracketed_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-square-bracketed-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height［source=0 target=701］".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth square bracket diagnostic suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height［source=0 target=701］"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height［source=0 target=701］"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height［source=0 target=701］"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_fullwidth_curly_braced_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-fullwidth-curly-braced-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height｛source=0 target=701｝".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth curly brace diagnostic suffix on invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat height｛source=0 target=701｝"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat height｛source=0 target=701｝"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat height｛source=0 target=701｝"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_height_slash_suffix_fails_closed() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-slash-suffix".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: "invalid heartbeat height/source=0 target=701".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect_err("unsupported suffix delimiter must not weaken invalid-height fail-closed behavior");

        assert_eq!(err, SettlementError::InvalidHeight { height: 701 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_slash_suffix_fails_closed() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-slash-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression/source=700 target=701".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect_err(
            "unsupported suffix delimiter must not weaken invalid-progression fail-closed behavior",
        );

        assert_eq!(err, SettlementError::InvalidHeight { height: 701 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_semicolon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-fullwidth-semicolon-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression；target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth semicolon suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression；target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression；target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression；target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_comma_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-comma-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression, target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("comma suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression, target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression, target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression, target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_ascii_semicolon_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-ascii-semicolon-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression; target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("ASCII semicolon suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression; target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression; target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression; target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_period_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-period-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression. target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("period suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression. target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression. target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression. target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_ideographic_full_stop_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-ideographic-full-stop-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression。target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("ideographic full stop suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression。target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression。target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression。target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_invalid_progression_fullwidth_comma_suffix_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-progression-fullwidth-comma-suffix".to_string(),
        );
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
            message: "invalid heartbeat progression，target height exceeded source sample"
                .to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("fullwidth comma suffix should preserve terminal invalid-progression compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: invalid heartbeat progression，target height exceeded source sample"
                    .to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: invalid heartbeat progression，target height exceeded source sample"
                            .to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: invalid heartbeat progression，target height exceeded source sample"
                    .to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_with_mixed_case_invalid_height_still_compensates() {
        let mut request = SettlementRequest::new(
            1,
            "0xdegraded-invalid-height-mixed-case".to_string(),
        );
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 701,
                latency_ms: 19,
            }),
            should_retry: false,
            degraded: true,
            message: " Invalid Heartbeat Height ".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("mixed-case invalid heartbeat height should remain terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: Invalid Heartbeat Height".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: Invalid Heartbeat Height".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: Invalid Heartbeat Height".to_string())
        );
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

    #[test]
    fn drive_minimal_settlement_retrying_heartbeat_with_failed_confirm_compensates_terminal_failure() {
        let mut request = SettlementRequest::new(1, "0xretry-failed-confirm".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: None,
            should_retry: true,
            degraded: false,
            message: "relay heartbeat retry pending".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Failed {
                reason: "target confirm timeout".to_string(),
            },
        )
        .expect("terminal confirm failure should compensate even if heartbeat is retry-pending");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "settlement confirm failed: target confirm timeout".to_string(),
                event: SettlementEvent {
                    phase: "settlement_confirm_failed",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "settlement confirm failed: target confirm timeout".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("settlement confirm failed: target confirm timeout".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_retrying_heartbeat_uses_settlement_scoped_fallback_when_message_sanitizes_empty() {
        let mut request = SettlementRequest::new(1, "0xretry-empty-heartbeat-message".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: None,
            should_retry: true,
            degraded: false,
            message: "\u{200B}\u{202E}\n\t\u{2066}".to_string(),
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
                reason: "heartbeat retry pending".to_string(),
            }
        );
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_confirm_without_embedded_heartbeat_metrics_fails_closed() {
        let mut request = SettlementRequest::new(1, "0xconfirm-sparse-overlay".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: None,
            should_retry: false,
            degraded: false,
            message: "healthy overlay".to_string(),
        };

        let err = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect_err("confirm without heartbeat evidence must fail closed");

        assert_eq!(err, SettlementError::InvalidHeight { height: 701 });
        assert_eq!(request.status, BridgeStatus::Pending);
    }

    #[test]
    fn drive_minimal_settlement_degraded_heartbeat_overrides_retry_pending_to_preserve_terminal_compensation() {
        let mut request = SettlementRequest::new(1, "0xdegraded-retrying-heartbeat".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: None,
            should_retry: true,
            degraded: true,
            message: "relay heartbeat retry pending".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 701 },
        )
        .expect("degraded heartbeat must resolve to terminal compensation");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: relay heartbeat retry pending".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: relay heartbeat retry pending".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted("heartbeat degraded: relay heartbeat retry pending".to_string())
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_invalid_heartbeat_progression_with_fullwidth_colon_allows_fail_closed_revert() {
        let mut request = SettlementRequest::new(1, "0xdegraded-invalid-heartbeat-fullwidth-colon".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 3,
                target_height: 9,
                latency_ms: 55,
            }),
            should_retry: false,
            degraded: true,
            message: "Invalid heartbeat progression：target height exceeded source sample".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Confirmed { height: 10 },
        )
        .expect("declared invalid heartbeat progression with fullwidth colon should still fail closed via compensation revert");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: Invalid heartbeat progression：target height exceeded source sample".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: Invalid heartbeat progression：target height exceeded source sample".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: Invalid heartbeat progression：target height exceeded source sample".to_string(),
            )
        );
    }

    #[test]
    fn drive_minimal_settlement_degraded_invalid_heartbeat_height_with_case_insensitive_prefix_allows_fail_closed_revert() {
        let mut request = SettlementRequest::new(1, "0xdegraded-invalid-heartbeat-casefold-prefix".to_string());
        let token = CapabilityToken {
            subject: "did:trn:settlement-operator".to_string(),
            capabilities: vec![SettlementCapability::Finalize, SettlementCapability::Revert],
        };
        let heartbeat = HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height: 0,
                target_height: 4,
                latency_ms: 21,
            }),
            should_retry: false,
            degraded: true,
            message: "INVALID HEARTBEAT HEIGHT - zero source sample".to_string(),
        };

        let out = drive_minimal_settlement(
            &mut request,
            &token,
            &heartbeat,
            SettlementConfirm::Failed {
                reason: "target confirm timeout".to_string(),
            },
        )
        .expect("case-insensitive invalid heartbeat height prefix should preserve fail-closed compensation path");

        assert_eq!(
            out,
            SettlementStep::Compensated {
                reason: "heartbeat degraded: INVALID HEARTBEAT HEIGHT - zero source sample".to_string(),
                event: SettlementEvent {
                    phase: "relay_heartbeat_degraded",
                    heartbeat_source_height: None,
                    heartbeat_target_height: None,
                    heartbeat_latency_ms: None,
                    confirm_height: None,
                    confirm_reason: Some(
                        "heartbeat degraded: INVALID HEARTBEAT HEIGHT - zero source sample".to_string(),
                    ),
                },
            }
        );
        assert_eq!(
            request.status,
            BridgeStatus::Reverted(
                "heartbeat degraded: INVALID HEARTBEAT HEIGHT - zero source sample".to_string(),
            )
        );
    }
}
