use trnm_bridge_poc::relay_heartbeat::{RelayHeartbeatConfig, RelayHeartbeatMonitor};

#[path = "x1_relay_heartbeat/x1_relay_heartbeat_smoke.rs"]
mod x1_relay_heartbeat_smoke;

#[path = "x1_relay_heartbeat/x1_relay_heartbeat_retries.rs"]
mod x1_relay_heartbeat_retries;

#[path = "x1_relay_heartbeat/x1_relay_heartbeat_config.rs"]
mod x1_relay_heartbeat_config;

#[path = "x1_relay_heartbeat/x1_relay_heartbeat_reason_clean.rs"]
mod x1_relay_heartbeat_reason_clean;

#[path = "x1_relay_heartbeat/x1_relay_heartbeat_reason_caps.rs"]
mod x1_relay_heartbeat_reason_caps;
