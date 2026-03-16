use std::path::PathBuf;

use crate::{
    adapter_error::is_idempotent_duplicate_ok,
    state::{load_ack_records, AdapterExecResult, PersistedAckHashes},
};

pub(crate) fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

pub(crate) fn persisted_ack_hashes_for_task(ack_log: &PathBuf, task_id: u64) -> PersistedAckHashes {
    let mut hashes = PersistedAckHashes {
        commit_tx_hash: None,
        reveal_tx_hash: None,
    };

    for ack in load_ack_records(ack_log).into_iter().rev() {
        if ack.task_id != task_id {
            continue;
        }
        if hashes.commit_tx_hash.is_none() {
            hashes.commit_tx_hash = ack.commit_tx_hash;
        }
        if hashes.reveal_tx_hash.is_none() {
            hashes.reveal_tx_hash = ack.reveal_tx_hash;
        }
        if hashes.commit_tx_hash.is_some() && hashes.reveal_tx_hash.is_some() {
            break;
        }
    }

    hashes
}
