use super::*;

pub(crate) fn task_status_from_node_status(status: &str) -> Option<TaskStatus> {
    match status {
        "Open" => Some(TaskStatus::Open),
        "Assigned" => Some(TaskStatus::Assigned),
        "Committed" => Some(TaskStatus::Committed),
        "Revealed" => Some(TaskStatus::Revealed),
        "Challenged" => Some(TaskStatus::Challenged),
        "Completed" => Some(TaskStatus::Completed),
        "Slashed" => Some(TaskStatus::Slashed),
        _ => None,
    }
}

pub(crate) fn is_legal_node_event_transition(
    event_type: &str,
    from_status: &str,
    to_status: &str,
) -> bool {
    matches!(
        (event_type, from_status, to_status),
        ("create", "NONE", "Open")
            | ("accept", "Open", "Assigned")
            | ("commit", "Assigned", "Committed")
            | ("reveal", "Committed", "Revealed")
            | ("challenge", "Revealed", "Challenged")
            | ("resolve", "Challenged", "Completed")
            | ("resolve", "Challenged", "Slashed")
            | ("timeout", "Committed", "Slashed")
            | ("timeout", "Revealed", "Completed")
            | ("timeout", "Challenged", "Completed")
    )
}

pub(crate) fn is_trusted_event_source(event: &NodeEventRecord) -> bool {
    let Some(actor) = normalize_actor_or_signer(&event.actor) else {
        return false;
    };
    let signer = event
        .signer
        .as_deref()
        .and_then(normalize_actor_or_signer)
        .unwrap_or_else(|| actor.clone());

    match event.event_type.as_str() {
        "accept" | "commit" | "reveal" | "challenge" | "create" => signer == actor,
        "resolve" => signer == actor && actor == "authority",
        "timeout" => signer == actor && matches!(actor.as_str(), "authority" | "system"),
        _ => false,
    }
}

pub(crate) fn filtered_node_events_for_task<'a>(
    task_id: u64,
    node_events: &'a [NodeEventRecord],
) -> impl Iterator<Item = &'a NodeEventRecord> {
    node_events.iter().filter(move |event| {
        event.task_id == task_id
            && is_legal_node_event_transition(
                event.event_type.as_str(),
                event.from_status.as_str(),
                event.to_status.as_str(),
            )
            && is_trusted_event_source(event)
    })
}

pub(crate) fn sorted_node_events_for_task<'a>(
    task_id: u64,
    node_events: &'a [NodeEventRecord],
) -> Vec<&'a NodeEventRecord> {
    let mut events: Vec<&NodeEventRecord> =
        filtered_node_events_for_task(task_id, node_events).collect();
    events.sort_by(|a, b| {
        (
            a.block_height,
            a.tx_id,
            a.ts_unix_ms,
            a.event_type.as_str(),
            a.from_status.as_str(),
            a.to_status.as_str(),
        )
            .cmp(&(
                b.block_height,
                b.tx_id,
                b.ts_unix_ms,
                b.event_type.as_str(),
                b.from_status.as_str(),
                b.to_status.as_str(),
            ))
    });
    events
}

fn adapter_kind_query_order(kind: &str) -> u8 {
    match kind {
        "commit" => 0,
        "reveal" => 1,
        _ => 2,
    }
}

pub(crate) fn sorted_task_adapter_records<'a>(
    task_id: u64,
    recs: &'a [AdapterRecord],
) -> Vec<&'a AdapterRecord> {
    let mut task_recs: Vec<&AdapterRecord> = recs
        .iter()
        .filter(|r| {
            r.task_id == task_id
                && r.status == "accepted"
                && matches!(r.kind.as_str(), "commit" | "reveal")
                && r.worker
                    .as_deref()
                    .and_then(normalize_actor_or_signer)
                    .is_some()
        })
        .collect();
    task_recs.sort_by(|a, b| {
        (
            a.ts,
            adapter_kind_query_order(&a.kind),
            a.worker
                .as_deref()
                .and_then(normalize_actor_or_signer)
                .unwrap_or_default(),
            a.tx_hash
                .as_deref()
                .map(normalize_tx_hash_lookup)
                .unwrap_or_default(),
            a.result_hash.as_deref().unwrap_or("").trim(),
        )
            .cmp(&(
                b.ts,
                adapter_kind_query_order(&b.kind),
                b.worker
                    .as_deref()
                    .and_then(normalize_actor_or_signer)
                    .unwrap_or_default(),
                b.tx_hash
                    .as_deref()
                    .map(normalize_tx_hash_lookup)
                    .unwrap_or_default(),
                b.result_hash.as_deref().unwrap_or("").trim(),
            ))
    });
    task_recs.dedup_by(|a, b| {
        a.kind == b.kind
            && a.worker
                .as_deref()
                .and_then(normalize_actor_or_signer)
                == b.worker
                    .as_deref()
                    .and_then(normalize_actor_or_signer)
            && a.tx_hash
                .as_deref()
                .map(normalize_tx_hash_lookup)
                == b.tx_hash
                    .as_deref()
                    .map(normalize_tx_hash_lookup)
            && a.result_hash.as_deref().map(str::trim)
                == b.result_hash.as_deref().map(str::trim)
    });
    task_recs
}

pub(crate) fn query_task_from_node_events(
    task_id: u64,
    node_events: &[NodeEventRecord],
) -> Option<TaskQueryResponse> {
    let mut version: u64 = 0;
    let mut status: Option<TaskStatus> = None;
    let mut worker: Option<String> = None;

    for event in sorted_node_events_for_task(task_id, node_events) {
        version += 1;
        if let Some(mapped) = task_status_from_node_status(event.to_status.as_str()) {
            status = Some(mapped);
        }
        if event.event_type == "accept"
            || event.event_type == "commit"
            || event.event_type == "reveal"
        {
            worker = normalize_actor_or_signer(&event.actor);
        }
    }

    status.map(|status| TaskQueryResponse {
        task_id,
        status,
        worker,
        bounty: 100,
        result_hash_hex: None,
        version,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    })
}

pub(crate) fn query_task_response(
    task_id: u64,
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
) -> Result<TaskQueryResponse> {
    let task_state_snapshot = load_task_state_snapshot()?;
    if let Some(out) = query_task_from_state_snapshot(task_id, &task_state_snapshot) {
        return Ok(out);
    }
    if let Some(out) = query_task_from_node_events(task_id, node_events) {
        return Ok(out);
    }

    let task_recs = sorted_task_adapter_records(task_id, recs);
    if task_recs.is_empty() {
        bail!("task not found: {}", task_id);
    }
    let has_commit = task_recs.iter().any(|r| r.kind == "commit");
    if !has_commit {
        bail!(
            "task not found: {} (adapter fallback requires persisted commit history)",
            task_id
        );
    }
    let has_reveal = task_recs.iter().any(|r| r.kind == "reveal");
    let status = if has_reveal {
        TaskStatus::Revealed
    } else if has_commit {
        TaskStatus::Committed
    } else {
        TaskStatus::Open
    };
    let worker = task_recs.iter().find_map(|r| r.worker.clone());
    let result_hash_hex = task_recs.iter().rev().find_map(|r| {
        if r.kind == "reveal" {
            r.result_hash.clone()
        } else {
            None
        }
    });
    Ok(TaskQueryResponse {
        task_id,
        status,
        worker,
        bounty: 100,
        result_hash_hex,
        version: task_recs.len() as u64,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    })
}
