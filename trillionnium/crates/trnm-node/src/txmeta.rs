use trnm_state::{ConsumptionRecordKey, StateStore};

use crate::types::MockTx;

pub(crate) fn task_id_of(tx: &MockTx) -> u64 {
    match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
        MockTx::SubmitConsumptionReceipt { receipt } => receipt.task_id,
        MockTx::ChallengeConsumptionReceipt { key, .. }
        | MockTx::ResolveConsumptionReceipt { key, .. } => key.task_id,
    }
}

pub(crate) fn actor_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::CreateTask { creator, .. } => creator.clone(),
        MockTx::AcceptTask { worker, .. } => worker.clone(),
        MockTx::Commit { worker, .. } => worker.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| format!("worker{}", task_id)),
        MockTx::Challenge { challenger, .. } => challenger.clone(),
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::SubmitConsumptionReceipt { receipt } => receipt.consumer_id.clone(),
        MockTx::ChallengeConsumptionReceipt { challenger, .. } => challenger.clone(),
        MockTx::ResolveConsumptionReceipt { resolver, .. } => resolver.clone(),
    }
}

pub(crate) fn verified_signer_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| "unknown_worker".to_string()),
        _ => actor_of(st, tx),
    }
}

pub(crate) fn challenger_of(tx: &MockTx) -> Option<String> {
    match tx {
        MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
        MockTx::ChallengeConsumptionReceipt { challenger, .. } => Some(challenger.clone()),
        MockTx::Resolve { .. } => None,
        MockTx::ResolveConsumptionReceipt { .. } => None,
        _ => None,
    }
}

fn is_canonical_receipt_event_actor_id(actor: &str) -> bool {
    !actor.is_empty()
        && actor == actor.trim()
        && actor.is_ascii()
        && !actor
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
        && !actor
            .chars()
            .any(|ch| matches!(ch, ',' | ';' | ':' | '|' | '/' | '\\'))
}

pub(crate) fn normalized_consumption_resolution_code(code: &str) -> Option<&str> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn challenger_from_consumption_resolution_code(code: &str) -> Option<String> {
    let challenger =
        normalized_consumption_resolution_code(code)?.strip_prefix("challenged_by:")?;
    if !is_canonical_receipt_event_actor_id(challenger) {
        return None;
    }
    Some(challenger.to_string())
}

pub(crate) fn consumption_record_key_of(tx: &MockTx) -> Option<ConsumptionRecordKey> {
    match tx {
        MockTx::SubmitConsumptionReceipt { receipt } => Some(ConsumptionRecordKey {
            task_id: receipt.task_id,
            consumer_id: receipt.consumer_id.clone(),
            output_hash: receipt.output_hash.clone(),
            billing_window_id: receipt.billing_window_id.clone(),
        }),
        MockTx::ChallengeConsumptionReceipt { key, .. }
        | MockTx::ResolveConsumptionReceipt { key, .. } => Some(ConsumptionRecordKey {
            task_id: key.task_id,
            consumer_id: key.consumer_id.clone(),
            output_hash: key.output_hash.clone(),
            billing_window_id: key.billing_window_id.clone(),
        }),
        _ => None,
    }
}

pub(crate) fn preapply_challenger_account_of(st: &StateStore, tx: &MockTx) -> Option<String> {
    match tx {
        MockTx::Resolve { task_id, .. } => st.get_task(*task_id).and_then(|task| task.challenger),
        MockTx::ResolveConsumptionReceipt { .. } => consumption_record_key_of(tx)
            .and_then(|key| st.consumption_record(&key))
            .and_then(|record| {
                record
                    .resolution_code
                    .as_deref()
                    .and_then(challenger_from_consumption_resolution_code)
            }),
        _ => challenger_of(tx),
    }
}

pub(crate) fn tx_hash_of(tx_id: u64) -> String {
    format!("0xmock{:016x}", tx_id)
}

pub(crate) fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
