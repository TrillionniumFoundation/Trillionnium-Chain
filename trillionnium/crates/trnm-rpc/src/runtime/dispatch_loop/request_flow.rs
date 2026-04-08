use super::*;

pub(super) fn handle_submit_message(
    channel: String,
    user_id: String,
    session_id: String,
    text: String,
    idempotency_key: String,
) -> Result<()> {
    let path = ingress_file();
    let _lock = acquire_market_file_lock(&path)?;

    let mut records = load_ingress_records();
    if let Some(found) = records.iter().rev().find(|r| {
        is_same_submit_message_idempotency_scope(
            r,
            &channel,
            &user_id,
            &session_id,
            &idempotency_key,
        )
    }) {
        println!("{}", serde_json::to_string_pretty(found)?);
        return Ok(());
    }

    // Quota gate applies to fresh ingress only. Existing idempotent records
    // must still replay successfully under tighter runtime limits.
    let max_bytes = submit_message_max_bytes() as usize;
    if text.len() > max_bytes {
        bail!(
            "submit-message text exceeds {} bytes limit (got {})",
            max_bytes,
            text.len()
        );
    }

    validate_submit_message_metadata(&text)?;

    let ts = now_ms();
    let request_id = make_request_id(&channel, &user_id, &session_id, &idempotency_key, ts);
    let task_id = next_ingress_task_id(&records)?;
    let rec = MessageIngressRecord {
        request_id,
        task_id,
        channel,
        user_id,
        session_id,
        text,
        idempotency_key,
        status: RequestStatus::Open.as_str().into(),
        created_at_unix_ms: ts,
        assigned_worker: None,
        assigned_at_unix_ms: None,
        model_output: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    records.push(rec.clone());
    save_ingress_records(&records)?;

    let out = MessageRequestQueryResponse {
        request_id: rec.request_id,
        task_id: rec.task_id,
        channel: rec.channel,
        user_id: rec.user_id,
        session_id: rec.session_id,
        text: rec.text,
        idempotency_key: rec.idempotency_key,
        status: rec.status,
        created_at_unix_ms: rec.created_at_unix_ms,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(super) fn handle_query_request(request_id: String) -> Result<()> {
    let records = load_ingress_records();
    let Some(rec) = records
        .into_iter()
        .rev()
        .find(|r| r.request_id == request_id)
    else {
        bail!("request not found: {}", request_id);
    };
    let out = MessageRequestQueryResponse {
        request_id: rec.request_id,
        task_id: rec.task_id,
        channel: rec.channel,
        user_id: rec.user_id,
        session_id: rec.session_id,
        text: rec.text,
        idempotency_key: rec.idempotency_key,
        status: rec.status,
        created_at_unix_ms: rec.created_at_unix_ms,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(super) fn handle_query_request_full(request_id: String, limit: usize) -> Result<()> {
    let limit = clamp_limit(
        "QueryRequestFull",
        limit,
        QUERY_FULL_LIMIT_DEFAULT,
        QUERY_FULL_LIMIT_MAX,
    );
    let records = load_ingress_records();
    let Some(rec) = records
        .into_iter()
        .rev()
        .find(|r| r.request_id == request_id)
    else {
        bail!("request not found: {}", request_id);
    };

    let node_events = load_node_events(NodeEventScanMode::Authoritative);
    let mut events = Vec::new();
    for e in filtered_node_events_for_task(rec.task_id, &node_events.events) {
        let Some(actor) = normalize_actor_or_signer(&e.actor) else {
            continue;
        };
        let signer = e
            .signer
            .as_deref()
            .and_then(normalize_actor_or_signer)
            .or_else(|| Some(actor.clone()));
        let tx_hash = match e.event_type.as_str() {
            "commit" => rec.commit_tx_hash.clone().or_else(|| e.tx_hash.clone()),
            "reveal" => rec.reveal_tx_hash.clone().or_else(|| e.tx_hash.clone()),
            _ => e.tx_hash.clone(),
        };
        let resolution_code = if e.event_type == "resolve" {
            rec.resolution_code
                .clone()
                .or_else(|| e.resolution_code.clone())
        } else {
            e.resolution_code.clone()
        };
        push_tail_limited(
            &mut events,
            EventQueryResponse {
                event_type: e.event_type.clone(),
                task_id: rec.task_id,
                from_status: e.from_status.clone(),
                to_status: e.to_status.clone(),
                actor,
                tx_id: e.tx_id,
                block_height: e.block_height,
                state_root: e.state_root.clone(),
                ts_unix_ms: e.ts_unix_ms,
                signer,
                challenger: e.challenger.clone(),
                tx_hash,
                resolution_code,
                treasury_delta: e.treasury_delta,
                challenger_delta: e.challenger_delta,
                bond_disposition: e.bond_disposition.clone(),
                metering: e.metering.clone(),
            },
            limit,
        );
    }

    let out = RequestFullQueryResponse {
        request: MessageRequestQueryResponse {
            request_id: rec.request_id,
            task_id: rec.task_id,
            channel: rec.channel,
            user_id: rec.user_id,
            session_id: rec.session_id,
            text: rec.text,
            idempotency_key: rec.idempotency_key,
            status: rec.status,
            created_at_unix_ms: rec.created_at_unix_ms,
        },
        verifier_status: rec.verifier_status,
        resolution_code: rec.resolution_code,
        result_hash: rec.result_hash,
        commit_tx_hash: rec.commit_tx_hash,
        reveal_tx_hash: rec.reveal_tx_hash,
        events,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(super) fn handle_dispatch_open(worker_id: String, limit: usize) -> Result<()> {
    let limit = clamp_limit(
        "DispatchOpen",
        limit,
        DISPATCH_OPEN_LIMIT_DEFAULT,
        DISPATCH_OPEN_LIMIT_MAX,
    );
    let path = ingress_file();
    let _lock = acquire_market_file_lock(&path)?;
    let mut records = load_ingress_records();
    let mut assigned = Vec::<MessageRequestQueryResponse>::new();
    let ts = now_ms();
    let mut n = 0usize;
    for rec in records.iter_mut() {
        if n >= limit {
            break;
        }
        if rec.status == RequestStatus::Open.as_str() {
            rec.status = transition_request_status(&rec.status, RequestStatus::Assigned)?;
            rec.assigned_worker = Some(worker_id.clone());
            rec.assigned_at_unix_ms = Some(ts);
            assigned.push(MessageRequestQueryResponse {
                request_id: rec.request_id.clone(),
                task_id: rec.task_id,
                channel: rec.channel.clone(),
                user_id: rec.user_id.clone(),
                session_id: rec.session_id.clone(),
                text: rec.text.clone(),
                idempotency_key: rec.idempotency_key.clone(),
                status: rec.status.clone(),
                created_at_unix_ms: rec.created_at_unix_ms,
            });
            n += 1;
        }
    }
    save_ingress_records(&records)?;
    println!("{}", serde_json::to_string_pretty(&assigned)?);
    Ok(())
}
