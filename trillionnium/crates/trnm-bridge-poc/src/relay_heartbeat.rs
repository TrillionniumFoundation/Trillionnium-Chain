#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHeartbeatConfig {
    pub interval_secs: u64,
    pub max_retry: u8,
}

impl RelayHeartbeatConfig {
    pub fn new(interval_secs: u64, max_retry: u8) -> Self {
        Self {
            interval_secs: interval_secs.max(1),
            max_retry: max_retry.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayHeartbeat {
    pub source_height: u64,
    pub target_height: u64,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatOutcome {
    pub heartbeat: Option<RelayHeartbeat>,
    pub should_retry: bool,
    pub degraded: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RelayHeartbeatMonitor {
    config: RelayHeartbeatConfig,
    consecutive_failures: u8,
}

impl RelayHeartbeatMonitor {
    pub fn new(config: RelayHeartbeatConfig) -> Self {
        Self {
            config,
            consecutive_failures: 0,
        }
    }

    pub fn interval_secs(&self) -> u64 {
        self.config.interval_secs
    }

    pub fn consecutive_failures(&self) -> u8 {
        self.consecutive_failures
    }

    pub fn record_success(
        &mut self,
        source_height: u64,
        target_height: u64,
        latency_ms: u64,
    ) -> HeartbeatOutcome {
        if source_height == 0 || target_height == 0 {
            self.consecutive_failures = self.config.max_retry;
            let message = "invalid heartbeat height".to_string();
            eprintln!(
                "[relay-heartbeat][degraded] failures={} reason={}",
                self.consecutive_failures, message
            );
            return HeartbeatOutcome {
                heartbeat: None,
                should_retry: false,
                degraded: true,
                message,
            };
        }

        if target_height > source_height {
            self.consecutive_failures = self.config.max_retry;
            let message = "invalid heartbeat progression".to_string();
            eprintln!(
                "[relay-heartbeat][degraded] failures={} reason={}",
                self.consecutive_failures, message
            );
            return HeartbeatOutcome {
                heartbeat: None,
                should_retry: false,
                degraded: true,
                message,
            };
        }

        self.consecutive_failures = 0;
        HeartbeatOutcome {
            heartbeat: Some(RelayHeartbeat {
                source_height,
                target_height,
                latency_ms,
            }),
            should_retry: false,
            degraded: false,
            message: "heartbeat ok".to_string(),
        }
    }

    pub fn record_failure(&mut self, reason: &str) -> HeartbeatOutcome {
        self.consecutive_failures = self
            .consecutive_failures
            .saturating_add(1)
            .min(self.config.max_retry);
        let degraded = self.consecutive_failures >= self.config.max_retry;
        let should_retry = !degraded;
        let normalized_reason = normalize_failure_reason(reason);

        if degraded {
            eprintln!(
                "[relay-heartbeat][degraded] failures={} reason={}",
                self.consecutive_failures, normalized_reason
            );
        }
        HeartbeatOutcome {
            heartbeat: None,
            should_retry,
            degraded,
            message: normalized_reason,
        }
    }
}

const MAX_FAILURE_REASON_CHARS: usize = 160;

fn is_disallowed_invisible_char(ch: char) -> bool {
    matches!(
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
            | '\u{2000}'
            | '\u{2001}'
            | '\u{2002}'
            | '\u{2003}'
            | '\u{2004}'
            | '\u{2005}'
            | '\u{2006}'
            | '\u{2007}'
            | '\u{2008}'
            | '\u{2009}'
            | '\u{200A}'
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

fn normalize_failure_reason(reason: &str) -> String {
    let sanitized: String = reason
        .chars()
        .map(|ch| {
            if ch.is_whitespace() || ch.is_control() || is_disallowed_invisible_char(ch) {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return "unknown heartbeat failure".to_string();
    }

    let mut normalized = String::new();
    for ch in collapsed.chars() {
        if normalized.chars().count() >= MAX_FAILURE_REASON_CHARS {
            normalized.pop();
            normalized.push('…');
            break;
        }
        normalized.push(ch);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::{normalize_failure_reason, RelayHeartbeatConfig, RelayHeartbeatMonitor};

    #[test]
    fn record_success_invalid_zero_height_fails_closed_without_retry_window() {
        let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(30, 3));

        let outcome = monitor.record_success(0, 42, 18);

        assert!(outcome.degraded);
        assert!(!outcome.should_retry);
        assert!(outcome.heartbeat.is_none());
        assert_eq!(outcome.message, "invalid heartbeat height");
        assert_eq!(monitor.consecutive_failures(), 3);
    }

    #[test]
    fn record_success_invalid_progression_fails_closed_without_retry_window() {
        let mut monitor = RelayHeartbeatMonitor::new(RelayHeartbeatConfig::new(30, 3));

        let outcome = monitor.record_success(41, 42, 18);

        assert!(outcome.degraded);
        assert!(!outcome.should_retry);
        assert!(outcome.heartbeat.is_none());
        assert_eq!(outcome.message, "invalid heartbeat progression");
        assert_eq!(monitor.consecutive_failures(), 3);
    }

    #[test]
    fn normalize_failure_reason_strips_cgj_for_replay_stability() {
        let raw = "target\u{034F} relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_alm_and_zwnj_for_replay_stability() {
        let raw = "target\u{061C} relay\u{200C} timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_halfwidth_hangul_filler_for_replay_stability() {
        let raw = "target\u{FFA0}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_collapses_nbsp_family_for_replay_stability() {
        let raw = "target\u{00A0}relay\u{2007}timeout\u{202F}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_soft_hyphen_for_replay_stability() {
        let raw = "target\u{00AD}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_mongolian_variation_selectors_for_replay_stability() {
        let raw = "target\u{180B}relay\u{180C}timeout\u{180D}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_mongolian_free_variation_selector_four_for_replay_stability() {
        let raw = "target\u{180F}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_collapses_medium_math_and_ideographic_spaces() {
        let raw = "target\u{205F}relay\u{3000}timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_collapses_general_punctuation_spaces_for_replay_stability() {
        let raw = "target\u{2000}relay\u{2001}timeout\u{2002}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_collapses_thin_space_family_for_replay_stability() {
        let raw = "target\u{2008}relay\u{2009}timeout\u{200A}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_collapses_crlf_and_unicode_separators_for_replay_stability() {
        let raw = "target\r\nrelay\u{2028}timeout\u{2029}signal\n";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_invisible_math_operators_and_mvs() {
        let raw = "target\u{2061} relay\u{2062} timeout\u{2063} signal\u{2064}\u{180E}";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_hangul_fillers_for_replay_stability() {
        let raw = "target\u{115F}relay\u{1160}timeout\u{3164}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_braille_blank_for_replay_stability() {
        let raw = "target\u{2800}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_bom_word_joiner_and_variation_selectors_for_replay_stability()
    {
        let raw = "target\u{FEFF}relay\u{2060}timeout\u{FE0F}signal\u{E0100}";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_plane14_tag_chars_for_replay_stability() {
        let raw = "target\u{E0001}relay\u{E0020}timeout\u{E007F}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_inhibit_symmetric_swapping_for_replay_stability() {
        let raw = "target\u{2065} relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_interlinear_annotation_controls_for_replay_stability() {
        let raw = "target\u{FFF9}relay\u{FFFA}timeout\u{FFFB}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_directional_marks_and_legacy_bidi_isolates_for_replay_stability() {
        let raw = "target\u{200E}\u{206A}relay\u{200F}timeout\u{206B}signal\u{206C}\u{206D}\u{206E}\u{206F}";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_bidi_embedding_isolates_for_replay_stability() {
        let raw = "target\u{2066}relay\u{2067}timeout\u{2068}signal\u{2069}";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_nested_directional_isolates_for_replay_stability() {
        let raw = "target\u{2066}\u{2067}relay\u{2068}timeout\u{2069}\u{2069}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_strips_mixed_bidi_marks_and_embedding_isolates_for_replay_stability() {
        let raw = "target\u{200E}\u{2066}relay\u{202E}timeout\u{2069}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_collapses_ogham_space_mark_for_replay_stability() {
        let raw = "target\u{1680}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_khmer_inherent_vowels_for_replay_stability() {
        let raw = "target\u{17B4}relay\u{17B5}timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_plane1_musical_controls_for_replay_stability() {
        let raw = "target\u{1D173}relay\u{1D174}timeout\u{1D17A}signal";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout signal");
    }

    #[test]
    fn normalize_failure_reason_collapses_braille_blank_for_replay_stability() {
        let raw = "target\u{2800}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_strips_mongolian_free_variation_selector_for_replay_stability() {
        let raw = "target\u{180F}relay timeout";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "target relay timeout");
    }

    #[test]
    fn normalize_failure_reason_uses_stable_fallback_when_empty_after_sanitize() {
        let raw = "\u{200B}\u{2060}\n\t\u{FEFF}";
        let normalized = normalize_failure_reason(raw);
        assert_eq!(normalized, "unknown heartbeat failure");
    }

    #[test]
    fn normalize_failure_reason_exact_cap_has_no_ellipsis() {
        let raw = "b".repeat(160);
        let normalized = normalize_failure_reason(&raw);
        assert_eq!(normalized.chars().count(), 160);
        assert_eq!(normalized, raw);
        assert!(!normalized.ends_with('…'));
    }

    #[test]
    fn normalize_failure_reason_enforces_bounded_max_len_with_ellipsis() {
        let raw = "a".repeat(220);
        let normalized = normalize_failure_reason(&raw);
        assert_eq!(normalized.chars().count(), 160);
        assert!(normalized.ends_with('…'));
    }
}
