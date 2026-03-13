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
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
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
            | '\u{180E}'
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
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
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
    )
        || ('\u{FE00}'..='\u{FE0F}').contains(&ch)
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
    for (idx, ch) in collapsed.chars().enumerate() {
        if idx >= MAX_FAILURE_REASON_CHARS {
            normalized.push('…');
            break;
        }
        normalized.push(ch);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::normalize_failure_reason;

    #[test]
    fn normalize_failure_reason_strips_cgj_for_replay_stability() {
        let raw = "target\u{034F} relay timeout";
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
}
