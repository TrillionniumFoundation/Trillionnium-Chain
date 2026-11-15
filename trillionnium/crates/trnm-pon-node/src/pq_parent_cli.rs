//! Explicit development-only paired native TLS and PQ History recovery CLI.
//! The history channel remains signed plaintext loopback. This is not a
//! production, private-task, WAN, custody or directory-rollback qualification.
use super::{ensure, input, need, number, spki, Configuration};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use trnm_pon_node::{public_submit::SubmitRecoveryPlan, Result};
#[path = "pq_parent_cli/config.rs"]
mod config;
#[path = "pq_parent_cli/recovery.rs"]
mod recovery;
#[path = "pq_parent_cli/service.rs"]
mod service;

/// Called immediately after reading the subcommand, before parsing options or
/// opening any configuration, packet, campaign or Node. Resume creates no plan.
pub(crate) fn capture_create(
    command: &str,
    started: Instant,
) -> Result<Option<SubmitRecoveryPlan>> {
    if command != "pq-parent-create" {
        return Ok(None);
    }
    let plan = SubmitRecoveryPlan {
        started,
        deadline: started
            .checked_add(Duration::from_secs(60))
            .ok_or("SUBMIT_RECOVERY_LIMITS")?,
        max_submit_attempts: 3,
        max_calls: 16,
        max_parent_packets: 1,
        retry_pause: Duration::from_millis(100),
    };
    plan.validate()?;
    Ok(Some(plan))
}

fn address(args: &BTreeMap<String, String>, key: &str, listening: bool) -> Result<SocketAddr> {
    let address: SocketAddr = need(args, key)?.parse().map_err(|_| "PQ_PARENT_ADDRESS")?;
    ensure(
        address.ip().is_loopback(),
        "PQ_PARENT_RECOVERY_LOOPBACK_ONLY",
    )?;
    ensure(listening || address.port() != 0, "PQ_PARENT_ADDRESS")?;
    Ok(address)
}

pub(crate) fn run(
    command: &str,
    args: &BTreeMap<String, String>,
    plan: Option<SubmitRecoveryPlan>,
) -> Result<Value> {
    const COMMON: &[&str] = &[
        "--development",
        "--store",
        "--workers",
        "--tls-config",
        "--tls-config-sha256",
        "--tls-cert",
        "--tls-key",
        "--tls-ca",
        "--witness-writer-key",
        "--history-policy-sha256",
        "--admission-bits",
        "--admission-ttl-ms",
    ];
    const RECOVERY: &[&str] = &[
        "--native-peer",
        "--history-peer",
        "--campaign",
        "--initial-sequence",
        "--packet",
    ];
    const CREATE: &[&str] = &[
        "--submit-deadline-ms",
        "--submit-attempts",
        "--submit-call-cap",
        "--submit-parent-depth",
    ];
    const SERVE: &[&str] = &["--native-listen", "--history-listen", "--seconds"];
    let serving = command == "pq-parent-tls-serve";
    let creating = command == "pq-parent-create";
    ensure(
        serving || creating || command == "pq-parent-resume",
        "PQ_PARENT_COMMAND",
    )?;
    ensure(
        args.keys().all(|key| {
            COMMON.contains(&key.as_str())
                || (serving && SERVE.contains(&key.as_str()))
                || (!serving && RECOVERY.contains(&key.as_str()))
                || (creating && CREATE.contains(&key.as_str()))
        }),
        "PQ_PARENT_OPTION",
    )?;
    ensure(
        args.get("--development").map(String::as_str) == Some("true"),
        "EXPLICIT_DEVELOPMENT_REQUIRED",
    )?;
    ensure(plan.is_some() == creating, "PQ_PARENT_EPOCH_SELECTION")?;
    let native = address(
        args,
        if serving {
            "--native-listen"
        } else {
            "--native-peer"
        },
        serving,
    )?;
    let history = address(
        args,
        if serving {
            "--history-listen"
        } else {
            "--history-peer"
        },
        serving,
    )?;
    ensure(serving || native != history, "PQ_PARENT_ENDPOINTS_DISTINCT")?;
    let workers = usize::try_from(number(args, "--workers", 1)?).map_err(|_| "PQ_TLS_WORKERS")?;
    ensure((1..=64).contains(&workers), "PQ_TLS_WORKERS")?;
    if serving {
        service::run(args, native, history, workers)
    } else {
        recovery::run(args, native, history, workers, plan)
    }
}

#[cfg(test)]
#[path = "pq_parent_cli/tests.rs"]
mod tests;
