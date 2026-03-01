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
        let normalized_reason = {
            let trimmed = reason.trim();
            if trimmed.is_empty() {
                "unknown heartbeat failure"
            } else {
                trimmed
            }
        };
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
            message: normalized_reason.to_string(),
        }
    }
}
