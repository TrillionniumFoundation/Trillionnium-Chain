use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub(crate) struct RunOnceOutput {
    pub(crate) task_id: u64,
    pub(crate) worker: String,
    pub(crate) result_hash: String,
    pub(crate) salt_hex: String,
    pub(crate) commit_hash: String,
    pub(crate) template_commit: String,
    pub(crate) template_reveal: String,
}

pub(crate) fn compute_result_and_salt(task_id: u64, payload: &str) -> (String, String) {
    use crate::execute_payload;
    execute_payload(payload, task_id)
}

pub(crate) fn compute_commit_hash(
    task_id: u64,
    result_hash: &str,
    salt_hex: &str,
    worker: &str,
) -> String {
    use crate::commitment;
    commitment(task_id, result_hash, salt_hex, worker)
}

pub(crate) fn commit_template(task_id: u64, worker: &str, commit_hash: &str, nonce: u64) -> String {
    format!(
        "trnm-node tx commit-result {} {} {} {}",
        task_id, worker, commit_hash, nonce
    )
}

pub(crate) fn reveal_template(task_id: u64, result_hash: &str, salt_hex: &str) -> String {
    format!(
        "trnm-node tx reveal-result {} {} {}",
        task_id, result_hash, salt_hex
    )
}

pub(crate) fn build_run_once_output(
    task_id: u64,
    worker: &str,
    result_hash: &str,
    salt_hex: &str,
    commit_hash: &str,
) -> RunOnceOutput {
    RunOnceOutput {
        task_id,
        worker: worker.to_string(),
        result_hash: result_hash.to_string(),
        salt_hex: salt_hex.to_string(),
        commit_hash: commit_hash.to_string(),
        template_commit: commit_template(task_id, worker, commit_hash, task_id),
        template_reveal: reveal_template(task_id, result_hash, salt_hex),
    }
}

pub(crate) fn submit_log_contract_line(submit_log: &Path) -> String {
    format!("submitted=true submit_log={}", submit_log.display())
}

#[cfg(test)]
mod tests {
    use super::{
        build_run_once_output, commit_template, compute_commit_hash, compute_result_and_salt,
        reveal_template, submit_log_contract_line,
    };

    #[test]
    fn build_commit_and_reveal_templates_are_stable() {
        let out = commit_template(7, "alice", "ccc", 7);
        assert_eq!(out, "trnm-node tx commit-result 7 alice ccc 7");
        let reveal = reveal_template(7, "result", "salt");
        assert_eq!(reveal, "trnm-node tx reveal-result 7 result salt");
    }

    #[test]
    fn build_run_once_output_carries_expected_fields() {
        let out = build_run_once_output(12, "bob", "rhash", "shex", "chash");
        assert_eq!(out.task_id, 12);
        assert_eq!(out.worker, "bob");
        assert_eq!(out.result_hash, "rhash");
        assert_eq!(
            out.template_commit,
            "trnm-node tx commit-result 12 bob chash 12"
        );
        assert_eq!(
            out.template_reveal,
            "trnm-node tx reveal-result 12 rhash shex"
        );
    }

    #[test]
    fn compute_result_and_salt_matches_core_payload_hashing() {
        let (result_hash, salt_hex) = compute_result_and_salt(7, "hello");
        assert_eq!(
            salt_hex,
            "0000000000000000000000000000000000000000000000000000000000000007"
        );
        assert_eq!(result_hash.len(), 64);
    }

    #[test]
    fn compute_commit_hash_stays_deterministic() {
        let commit = compute_commit_hash(7, "r", "s", "bob");
        assert!(commit.len() == 64);
    }

    #[test]
    fn submit_log_contract_line_keeps_operator_handoff_tokens_stable() {
        let line = submit_log_contract_line(std::path::Path::new("logs/submit.jsonl"));
        assert_eq!(line, "submitted=true submit_log=logs/submit.jsonl");
        assert_eq!(line.matches("submitted=true").count(), 1);
        assert_eq!(line.matches("submit_log=").count(), 1);
    }
}
