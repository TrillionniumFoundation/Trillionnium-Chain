use crate::envpaths::{ingress_file, submit_message_max_bytes};
use crate::ingress::{
    is_same_submit_message_idempotency_scope, load_ingress_records, next_ingress_task_id,
    save_ingress_records,
};
use crate::market_io::acquire_market_file_lock;
use crate::rpc_util::clamp_limit;
use crate::runtime::make_request_id;
use crate::validate::{transition_request_status, validate_submit_message_metadata};
use crate::{MessageIngressRecord, MessageRequestQueryResponse};
use anyhow::{bail, Result};
use trnm_types::RequestStatus;

pub(crate) const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
pub(crate) const DISPATCH_OPEN_LIMIT_MAX: usize = 100;

fn request_query_response(rec: &MessageIngressRecord) -> MessageRequestQueryResponse {
    MessageRequestQueryResponse {
        request_id: rec.request_id.clone(),
        task_id: rec.task_id,
        channel: rec.channel.clone(),
        user_id: rec.user_id.clone(),
        session_id: rec.session_id.clone(),
        text: rec.text.clone(),
        idempotency_key: rec.idempotency_key.clone(),
        status: rec.status.clone(),
        created_at_unix_ms: rec.created_at_unix_ms,
    }
}

pub(crate) fn handle_submit_message(
    channel: String,
    user_id: String,
    session_id: String,
    text: String,
    idempotency_key: String,
    now_unix_ms: u128,
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

    let max_bytes = submit_message_max_bytes() as usize;
    if text.len() > max_bytes {
        bail!(
            "submit-message text exceeds {} bytes limit (got {})",
            max_bytes,
            text.len()
        );
    }

    validate_submit_message_metadata(&text)?;

    let request_id = make_request_id(&channel, &user_id, &session_id, &idempotency_key, now_unix_ms);
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
        created_at_unix_ms: now_unix_ms,
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

    let out = request_query_response(&rec);
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_dispatch_open(
    worker_id: String,
    limit: usize,
    now_unix_ms: u128,
) -> Result<()> {
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
    let mut n = 0usize;
    for rec in records.iter_mut() {
        if n >= limit {
            break;
        }
        if rec.status == RequestStatus::Open.as_str() {
            rec.status = transition_request_status(&rec.status, RequestStatus::Assigned)?;
            rec.assigned_worker = Some(worker_id.clone());
            rec.assigned_at_unix_ms = Some(now_unix_ms);
            assigned.push(request_query_response(rec));
            n += 1;
        }
    }

    if !assigned.is_empty() {
        save_ingress_records(&records)?;
    }

    println!("{}", serde_json::to_string_pretty(&assigned)?);
    Ok(())
}
