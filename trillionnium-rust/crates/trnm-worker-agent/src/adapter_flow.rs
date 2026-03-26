use std::path::PathBuf;

use crate::{
    adapter_error::is_idempotent_duplicate_ok,
    state::{load_ack_records, AdapterExecResult, PersistedAckHashes},
    trim_boundary_audit_fillers,
};

pub(crate) fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

fn normalize_persisted_tx_hash(tx_hash: Option<String>) -> Option<String> {
    tx_hash.and_then(|hash| {
        let trimmed = trim_boundary_audit_fillers(&hash);
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
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
            hashes.commit_tx_hash = normalize_persisted_tx_hash(ack.commit_tx_hash);
        }
        if hashes.reveal_tx_hash.is_none() {
            hashes.reveal_tx_hash = normalize_persisted_tx_hash(ack.reveal_tx_hash);
        }
        if hashes.commit_tx_hash.is_some() && hashes.reveal_tx_hash.is_some() {
            break;
        }
    }

    hashes
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::persisted_ack_hashes_for_task;
    use crate::{append_ack, now_ms};

    #[test]
    fn persisted_ack_hashes_ignore_blank_receipt_values_when_scanning_backwards() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-blank-hash-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            501,
            "accepted",
            Some("commit-ok".to_string()),
            Some("reveal-ok".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write baseline ack");
        append_ack(
            &ack_log,
            501,
            "accepted",
            Some("   ".to_string()),
            Some("\n\t".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-2".to_string()),
        )
        .expect("write blank hash ack");

        let hashes = persisted_ack_hashes_for_task(&ack_log, 501);
        assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-ok"));
        assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-ok"));

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn persisted_ack_hashes_keep_fail_closed_when_only_blank_receipt_values_exist() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-blank-only-hash-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            502,
            "accepted",
            Some("  ".to_string()),
            Some("\u{2003}".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write blank-only hash ack");

        let hashes = persisted_ack_hashes_for_task(&ack_log, 502);
        assert_eq!(hashes.commit_tx_hash, None);
        assert_eq!(hashes.reveal_tx_hash, None);

        let _ = std::fs::remove_file(&ack_log);
    }

    #[test]
    fn persisted_ack_hashes_trim_bom_and_zero_width_receipt_fillers() {
        let ack_log = std::env::temp_dir().join(format!(
            "trnm-worker-agent-invisible-fillers-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&ack_log);

        append_ack(
            &ack_log,
            503,
            "accepted",
            Some("\u{feff}\u{200b}commit-ok\u{2060}".to_string()),
            Some("\u{200d}reveal-ok\u{200c}".to_string()),
            Some("idempotent_ok".to_string()),
            Some("run-1".to_string()),
        )
        .expect("write filler-padded hash ack");

        let hashes = persisted_ack_hashes_for_task(&ack_log, 503);
        assert_eq!(hashes.commit_tx_hash.as_deref(), Some("commit-ok"));
        assert_eq!(hashes.reveal_tx_hash.as_deref(), Some("reveal-ok"));

        let _ = std::fs::remove_file(&ack_log);
    }
}
