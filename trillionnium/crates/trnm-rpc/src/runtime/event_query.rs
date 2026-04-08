use super::*;

pub(crate) fn query_events_response(
    task_id: u64,
    limit: usize,
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
) -> Result<Vec<EventQueryResponse>> {
    let limit = clamp_limit(
        "QueryEvents",
        limit,
        QUERY_EVENTS_LIMIT_DEFAULT,
        QUERY_EVENTS_LIMIT_MAX,
    );
    let mut events = Vec::new();

    for e in sorted_node_events_for_task(task_id, node_events) {
        let Some(actor) = normalize_actor_or_signer(&e.actor) else {
            continue;
        };
        let signer = e
            .signer
            .as_deref()
            .and_then(normalize_actor_or_signer)
            .or_else(|| Some(actor.clone()));
        push_tail_limited(
            &mut events,
            EventQueryResponse {
                event_type: e.event_type.clone(),
                task_id,
                from_status: e.from_status.clone(),
                to_status: e.to_status.clone(),
                actor,
                tx_id: e.tx_id,
                block_height: e.block_height,
                state_root: e.state_root.clone(),
                ts_unix_ms: e.ts_unix_ms,
                signer,
                challenger: e.challenger.clone(),
                tx_hash: e.tx_hash.clone(),
                resolution_code: e.resolution_code.clone(),
                treasury_delta: e.treasury_delta,
                challenger_delta: e.challenger_delta,
                bond_disposition: e.bond_disposition.clone(),
                metering: e.metering.clone(),
            },
            limit,
        );
    }

    if events.is_empty() {
        let mut tx_id = 1u64;
        let mut has_commit = false;
        for r in sorted_task_adapter_records(task_id, recs) {
            let Some(actor) = r.worker.as_deref().and_then(normalize_actor_or_signer) else {
                continue;
            };
            let kind = r.kind.clone();
            if kind == "reveal" && !has_commit {
                continue;
            }
            let Some((from_status, to_status)) = (match kind.as_str() {
                "commit" => Some(("Assigned".to_string(), "Committed".to_string())),
                "reveal" => Some(("Committed".to_string(), "Revealed".to_string())),
                _ => None,
            }) else {
                continue;
            };

            let tx_hash = r.tx_hash.clone().and_then(|v| {
                let normalized = normalize_tx_hash_lookup(&v);
                if is_hex_like_tx_hash(&normalized) {
                    Some(normalized)
                } else {
                    None
                }
            });

            push_tail_limited(
                &mut events,
                EventQueryResponse {
                    event_type: kind.clone(),
                    task_id,
                    from_status,
                    to_status,
                    actor: actor.clone(),
                    tx_id,
                    block_height: tx_id,
                    state_root: "adapter_state".into(),
                    ts_unix_ms: r.ts as u128,
                    signer: Some(actor),
                    challenger: None,
                    tx_hash,
                    resolution_code: None,
                    treasury_delta: None,
                    challenger_delta: None,
                    bond_disposition: None,
                    metering: None,
                },
                limit,
            );
            if kind == "commit" {
                has_commit = true;
            }
            tx_id += 1;
        }
    }

    if events.is_empty() {
        bail!("events not found for task_id={}", task_id);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_events_response_fallback_sorts_and_dedupes_replayed_adapter_rows() {
        let recs = vec![
            AdapterRecord {
                ts: 20,
                kind: "reveal".into(),
                task_id: 77,
                worker: Some(" worker-z ".into()),
                result_hash: Some("0xdef".into()),
                status: "accepted".into(),
                tx_hash: Some("0XDEF".into()),
            },
            AdapterRecord {
                ts: 10,
                kind: "commit".into(),
                task_id: 77,
                worker: Some(" worker-z\u{200b}".into()),
                result_hash: None,
                status: "accepted".into(),
                tx_hash: Some(" tx_hash=0xabc ".into()),
            },
            AdapterRecord {
                ts: 10,
                kind: "commit".into(),
                task_id: 77,
                worker: Some("worker-z".into()),
                result_hash: None,
                status: "accepted".into(),
                tx_hash: Some("0XABC".into()),
            },
        ];

        let out = query_events_response(77, 20, &[], &recs).expect("events expected");
        assert_eq!(out.len(), 2, "replayed canonical adapter rows must dedupe");
        assert_eq!(out[0].event_type, "commit");
        assert_eq!(out[0].tx_hash.as_deref(), Some("0xabc"));
        assert_eq!(out[1].event_type, "reveal");
        assert_eq!(out[1].tx_hash.as_deref(), Some("0xdef"));
    }
}
