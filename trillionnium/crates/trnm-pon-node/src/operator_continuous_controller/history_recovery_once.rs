//! New protected local request schema. The existing V5 signed view, allocation
//! and journal namespaces keep their exact meanings. This one-shot path starts
//! no listener and never publishes an unfinished Node to a controller.
use super::*;
use crate::HistoryRecoverySelection;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRecoveryLaunch {
    schema: String,
    source_commit: String,
    node_policy_source: String,
    registry2_package: String,
    store: PathBuf,
    startup_wall_seconds: u64,
    workers: usize,
    inputs: policy::Inputs,
    selection: HistoryRecoverySelection,
    source: SocketAddr,
    raw_page: String,
}

/// Decode only the bounded externally pinned configuration here. Actual Page,
/// hex, packet, W1 and State processing remain inside the journal-backed scope.
/// The fixed concrete-source Host permit is required even for loopback input.
pub fn resume_pinned_history_once(outside: OutsideLaunch<'_>, started: Instant) -> Result<Value> {
    let raw = held_configuration(outside.path, MAX_FRAME_BYTES as u64)?;
    ensure(
        crate::operator_task_policy::digest_bytes(&raw) == outside.sha256,
        "OWNER_CONTINUOUS_HISTORY_RECOVERY_LAUNCH_SHA",
    )?;
    let config: HistoryRecoveryLaunch = serde_json::from_slice(&raw)?;
    ensure(
        config.schema == "restricted-owner-continuous-history-recovery-launch-v1"
            && config.source_commit == outside.source_commit
            && config.node_policy_source == outside.node_policy_source
            && config.registry2_package == outside.registry2_package
            && config.store.is_absolute()
            && (1..=2580).contains(&config.startup_wall_seconds)
            && [1, 2, 4, 8].contains(&config.workers),
        "OWNER_CONTINUOUS_HISTORY_RECOVERY_OUTSIDE_LAUNCH",
    )?;
    policy::validate_protected_inputs(
        &config.inputs,
        outside.registry_key,
        outside.task_key,
        outside.source_commit,
        outside.node_policy_source,
        outside.registry2_package,
    )
    .map_err(|_| "OWNER_CONTINUOUS_PROTECTED_CONTEXT")?;
    let deadline = started
        .checked_add(Duration::from_secs(config.startup_wall_seconds))
        .ok_or("OWNER_CONTINUOUS_DEADLINE")?;
    ensure(Instant::now() < deadline, "OWNER_CONTINUOUS_DEADLINE")?;
    let mut held = Node::open_operator_continuous_history_recovery(
        &config.store,
        config.inputs,
        deadline,
        config.workers,
        config.selection,
    )?;
    let (result, start_error, completed) =
        match held.resume_from(config.source, config.raw_page.as_bytes(), ingress::now()?) {
            Ok(value) => (Some(serde_json::to_value(value)?), None, value.completed),
            Err(error) => (None, Some(error.to_string()), false),
        };
    // Metadata readback and close errors must not erase an actual durable
    // admission/activation outcome. A failed close creates no invented receipt.
    let (active, active_error) = match held.active() {
        Ok((p, g)) => (Some(json!({"parent":hex::encode(p),"generation":g})), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (head, head_error) = match held.journal_head() {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (ready_released, closed, finalization_error) = if completed {
        match held.into_ready() {
            Ok((node, _, _)) => (true, Some(node.close_continuous_checkpoint()), None),
            Err(error) => (false, None, Some(error.to_string())),
        }
    } else {
        (false, Some(held.close_checkpoint()), None)
    };
    let (checkpoint, close_error) = match closed {
        Some(Ok(value)) => (Some(value), None),
        Some(Err(error)) => (None, Some(error.to_string())),
        None => (None, None),
    };
    let completed = completed
        && ready_released
        && checkpoint.is_some()
        && close_error.is_none()
        && active_error.is_none()
        && head_error.is_none();
    Ok(
        json!({"schema":"restricted-owner-continuous-history-recovery-result-v1",
        "result":result,"start_error":start_error,"ready_released":ready_released,
        "finalization_error":finalization_error,"checkpoint":checkpoint,"close_error":close_error,
        "active":active,"active_readback_error":active_error,
        "journal_head_before_close":head,"journal_readback_error":head_error,
        "completed":completed,"durable_result_preserved":true,
        "receiver_listener_started":false,"public_network_ready":false}),
    )
}
