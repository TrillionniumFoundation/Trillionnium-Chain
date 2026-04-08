use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::collections::BTreeMap;
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command as ProcCommand, Output, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod assigned;
mod audit;
mod cli;
mod dispatch;
mod flush;
mod flush_submission;
mod proof_adapter;
mod workflow;
mod workflow_ops;

#[cfg(test)]
pub(crate) use audit::{
    audit_export_index_path, build_audit_export_index, build_provenance_fingerprint,
    detect_audit_export_format, query_audit_export_by_provenance_fingerprint,
    query_audit_export_by_task_id, render_enterprise_audit_markdown, to_enterprise_audit_export,
    validate_audit_export_index, AuditExportFormat, AuditExportIndex, EnterpriseAuditExportRecord,
    QueryAuditOutput,
};
use audit::{handle_export_audit, handle_query_audit};
use cli::Args;
use dispatch::dispatch_command;
#[cfg(test)]
use proof_adapter::build_proof_adapter;
use proof_adapter::ProofAdapter;
use trnm_types::RequestStatus;
use wait_timeout::ChildExt;

const DEFAULT_TX_ADAPTER_MAX_RETRIES: u32 = 3;
const DEFAULT_TX_ADAPTER_BACKOFF_MS: u64 = 200;
const DEFAULT_LLM_ADAPTER_MAX_RETRIES: u32 = 2;
const DEFAULT_LLM_ADAPTER_BACKOFF_MS: u64 = 200;
const DEFAULT_LLM_ADAPTER_TIMEOUT_MS: u64 = 10_000;

const TX_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_TX_ADAPTER_MAX_RETRIES";
const TX_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_TX_ADAPTER_BACKOFF_MS";
const LLM_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_LLM_ADAPTER_MAX_RETRIES";
const LLM_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_LLM_ADAPTER_BACKOFF_MS";
const LLM_ADAPTER_TIMEOUT_ENV: &str = "TRNM_LLM_ADAPTER_TIMEOUT_MS";
pub(crate) const PROOF_ADAPTER_ENV: &str = "TRNM_PROOF_ADAPTER";
pub(crate) const WORKER_EVENT_LOG_ENV: &str = "TRNM_WORKER_EVENT_LOG";
pub(crate) const WORKER_PROGRESS_LOG_ENV: &str = "TRNM_WORKER_PROGRESS_LOG";

const RC_OK: i32 = 0;
const RC_DUPLICATE: i32 = 9;
const RC_NONCE_REJECTED: i32 = 10;
const RC_SLO_VIOLATION: i32 = 11;
pub(crate) const RC_SKIPPED: i32 = -1;

#[derive(Debug, Clone)]
pub(crate) struct PersistedAckHashes {
    pub(crate) commit_tx_hash: Option<String>,
    pub(crate) reveal_tx_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerState {
    last_task_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SubmissionRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) task_id: u64,
    pub(crate) worker: String,
    pub(crate) nonce: Option<u64>,
    pub(crate) commit_hash: String,
    pub(crate) result_hash: String,
    pub(crate) salt_hex: String,
    pub(crate) commit_cmd: String,
    pub(crate) reveal_cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MessageIngressRecord {
    pub(crate) request_id: String,
    pub(crate) task_id: u64,
    pub(crate) channel: String,
    pub(crate) user_id: String,
    pub(crate) session_id: String,
    pub(crate) text: String,
    pub(crate) idempotency_key: String,
    pub(crate) status: String,
    pub(crate) created_at_unix_ms: u128,
    #[serde(default)]
    pub(crate) assigned_worker: Option<String>,
    #[serde(default)]
    pub(crate) assigned_at_unix_ms: Option<u128>,
    #[serde(default)]
    pub(crate) model_output: Option<String>,
    #[serde(default)]
    pub(crate) provider_request_id: Option<String>,
    #[serde(default)]
    pub(crate) provenance_schema_version: Option<String>,
    #[serde(default)]
    pub(crate) llm_provenance: Option<LlmProvenanceRecord>,
    #[serde(default)]
    pub(crate) result_hash: Option<String>,
    #[serde(default)]
    pub(crate) verifier_status: Option<String>,
    #[serde(default)]
    pub(crate) resolution_code: Option<String>,
    #[serde(default)]
    pub(crate) commit_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reveal_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) adapter_error: Option<String>,
    #[serde(default)]
    pub(crate) reputation_delta: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LlmProvenanceRecord {
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) adapter: Option<String>,
    #[serde(default)]
    pub(crate) agent_protocol: Option<String>,
    #[serde(default)]
    pub(crate) compliance_profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AckRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) commit_tx_hash: Option<String>,
    pub(crate) reveal_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) run_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkerEvent {
    pub(crate) ts_unix_ms: u128,
    pub(crate) run_id: String,
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) reason_code: String,
    pub(crate) commit_rc: i32,
    pub(crate) reveal_rc: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProgressRecord {
    pub(crate) ts_unix_ms: u128,
    pub(crate) run_id: String,
    pub(crate) task_id: u64,
    pub(crate) state: String,
    pub(crate) note: String,
}

#[derive(Debug)]
pub(crate) struct AdapterExecResult {
    pub(crate) ok: bool,
    pub(crate) rc: i32,
    pub(crate) tx_hash: Option<String>,
    pub(crate) terminal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetryPolicy {
    pub(crate) max_retries: u32,
    pub(crate) backoff_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlmAdapterPolicy {
    pub(crate) retry: RetryPolicy,
    pub(crate) timeout_ms: u64,
}

pub(crate) fn commitment(
    task_id: u64,
    result_hash_hex: &str,
    salt_hex: &str,
    worker: &str,
) -> String {
    let payload = format!("{}|{}|{}|{}", task_id, result_hash_hex, salt_hex, worker);
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

pub(crate) fn next_task_id(state: &PathBuf) -> Result<u64> {
    let mut s = if state.exists() {
        serde_json::from_str::<WorkerState>(&fs::read_to_string(state)?)?
    } else {
        WorkerState { last_task_id: 1000 }
    };
    s.last_task_id += 1;
    fs::write(state, serde_json::to_string_pretty(&s)?)?;
    Ok(s.last_task_id)
}

pub(crate) fn execute_payload(payload: &str, task_id: u64) -> (String, String) {
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    let result_hash = hex::encode(h.finalize());
    let salt_hex = format!("{:064x}", task_id);
    (result_hash, salt_hex)
}

pub(crate) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn append_json_line(path: &PathBuf, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

pub(crate) fn append_submission(
    submit_log: &PathBuf,
    task_id: u64,
    worker: &str,
    commit_hash: &str,
    result_hash: &str,
    salt_hex: &str,
) -> Result<()> {
    let nonce = task_id;
    let commit_cmd = format!(
        "trnm-node tx commit-result {} {} {} {}",
        task_id, worker, commit_hash, nonce
    );
    let reveal_cmd = format!(
        "trnm-node tx reveal-result {} {} {}",
        task_id, result_hash, salt_hex
    );
    let rec = SubmissionRecord {
        ts_unix_ms: now_ms(),
        task_id,
        worker: worker.to_string(),
        nonce: Some(nonce),
        commit_hash: commit_hash.to_string(),
        result_hash: result_hash.to_string(),
        salt_hex: salt_hex.to_string(),
        commit_cmd,
        reveal_cmd,
    };
    let line = serde_json::to_string(&rec)?;
    append_json_line(submit_log, &line)
}

fn load_ack_records(ack_log: &PathBuf) -> Vec<AckRecord> {
    if !ack_log.exists() {
        return vec![];
    }
    fs::read_to_string(ack_log)
        .ok()
        .map(|raw| {
            raw.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|line| serde_json::from_str::<AckRecord>(line).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn load_acked(ack_log: &PathBuf) -> HashSet<u64> {
    load_ack_records(ack_log)
        .into_iter()
        .filter(|rec| rec.status == "accepted")
        .map(|rec| rec.task_id)
        .collect()
}

pub(crate) struct TaskExecutionLock {
    path: PathBuf,
}

impl Drop for TaskExecutionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn task_lock_path(ack_log: &PathBuf, task_id: u64) -> PathBuf {
    let parent = ack_log
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let base = ack_log
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("trnm-worker-agent-acks.jsonl");
    parent.join(format!(".{base}.task-{task_id}.lock"))
}

pub(crate) fn try_acquire_task_lock(
    ack_log: &PathBuf,
    task_id: u64,
) -> Result<Option<TaskExecutionLock>> {
    let path = task_lock_path(ack_log, task_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(Some(TaskExecutionLock { path })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn is_task_acked(ack_log: &PathBuf, task_id: u64) -> bool {
    load_acked(ack_log).contains(&task_id)
}

pub(crate) fn load_ingress_records(path: &PathBuf) -> Result<Vec<MessageIngressRecord>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MessageIngressRecord>(l).ok())
        .collect())
}

pub(crate) fn save_ingress_records(path: &PathBuf, records: &[MessageIngressRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::new();
    for rec in records {
        out.push_str(&serde_json::to_string(rec)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

pub(crate) fn transition_request_status(current: &str, to: RequestStatus) -> Result<String> {
    let from = RequestStatus::parse(current).map_err(|e| anyhow::anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}

pub(crate) fn append_ack(
    ack_log: &PathBuf,
    task_id: u64,
    status: &str,
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
    reason_code: Option<String>,
    run_id: Option<String>,
) -> Result<()> {
    let rec = AckRecord {
        ts_unix_ms: now_ms(),
        task_id,
        status: status.to_string(),
        commit_tx_hash,
        reveal_tx_hash,
        reason_code,
        run_id,
    };
    let line = serde_json::to_string(&rec)?;
    append_json_line(ack_log, &line)
}

pub(crate) fn append_event(event_log: &PathBuf, event: &WorkerEvent) -> Result<()> {
    let line = serde_json::to_string(event)?;
    append_json_line(event_log, &line)
}

pub(crate) fn append_progress(progress_log: &PathBuf, rec: &ProgressRecord) -> Result<()> {
    let line = serde_json::to_string(rec)?;
    append_json_line(progress_log, &line)
}

pub(crate) fn resolve_path_arg_from_env(
    path: PathBuf,
    env_name: &str,
    default_path: &str,
) -> PathBuf {
    if path == PathBuf::from(default_path) {
        if let Some(value) = env::var_os(env_name) {
            if !value.is_empty() {
                return PathBuf::from(value);
            }
        }
    }
    path
}

fn is_receipt_quote_wrapper(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '〈'
            | '〉'
            | '《'
            | '》'
            | '⟨'
            | '⟩'
            | '「'
            | '」'
            | '『'
            | '』'
    )
}

fn is_receipt_bracket_wrapper(ch: char) -> bool {
    matches!(
        ch,
        '(' | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
            | '（'
            | '）'
            | '［'
            | '］'
            | '｛'
            | '｝'
            | '＜'
            | '＞'
            | '【'
            | '】'
            | '〔'
            | '〕'
            | '〖'
            | '〗'
    )
}

fn normalize_candidate_tx_hash(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || is_receipt_bracket_wrapper(c)
                || matches!(c, ',' | ';' | '.' | ':' | '，' | '；' | '。' | '：')
                || c.is_control()
                || is_invisible_filler(c)
        })
        .trim_end_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || is_receipt_bracket_wrapper(c)
                || matches!(c, ',' | ';' | '，' | '；')
                || c.is_control()
                || is_invisible_filler(c)
        })
        .trim();
    let normalized = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned);

    if normalized.len() >= 8
        && normalized.len() <= 128
        && normalized.chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(normalized.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_tx_hash(text: &str) -> Option<String> {
    const PREFIXES: &[&str] = &[
        "tx_hash=",
        "tx_hash =",
        "tx_hash:",
        "tx_hash :",
        "TX_HASH=",
        "TX_HASH =",
        "TX_HASH:",
        "TX_HASH :",
        "tx-hash=",
        "tx-hash =",
        "tx-hash:",
        "tx-hash :",
        "TX-HASH=",
        "TX-HASH =",
        "TX-HASH:",
        "TX-HASH :",
        "tx hash=",
        "tx hash =",
        "tx hash:",
        "tx hash :",
        "TX HASH=",
        "TX HASH =",
        "TX HASH:",
        "TX HASH :",
        "txHash=",
        "txHash =",
        "txHash:",
        "txHash :",
        "TXHASH=",
        "TXHASH =",
        "TXHASH:",
        "TXHASH :",
        "txhash=",
        "txhash =",
        "txhash:",
        "txhash :",
        "transaction_hash=",
        "transaction_hash =",
        "transaction_hash:",
        "transaction_hash :",
        "TRANSACTION_HASH=",
        "TRANSACTION_HASH =",
        "TRANSACTION_HASH:",
        "TRANSACTION_HASH :",
        "transaction-hash=",
        "transaction-hash =",
        "transaction-hash:",
        "transaction-hash :",
        "TRANSACTION-HASH=",
        "TRANSACTION-HASH =",
        "TRANSACTION-HASH:",
        "TRANSACTION-HASH :",
        "transaction hash=",
        "transaction hash =",
        "transaction hash:",
        "transaction hash :",
        "TRANSACTION HASH=",
        "TRANSACTION HASH =",
        "TRANSACTION HASH:",
        "TRANSACTION HASH :",
        "transactionHash=",
        "transactionHash =",
        "transactionHash:",
        "transactionHash :",
        "TRANSACTIONHASH=",
        "TRANSACTIONHASH =",
        "TRANSACTIONHASH:",
        "TRANSACTIONHASH :",
        "transactionhash=",
        "transactionhash =",
        "transactionhash:",
        "transactionhash :",
        "\"tx_hash\":",
        "\"tx_hash\" :",
        "\"TX_HASH\":",
        "\"TX_HASH\" :",
        "\"tx-hash\":",
        "\"tx-hash\" :",
        "\"TX-HASH\":",
        "\"TX-HASH\" :",
        "\"tx hash\":",
        "\"tx hash\" :",
        "\"TX HASH\":",
        "\"TX HASH\" :",
        "\"txHash\":",
        "\"txHash\" :",
        "\"TXHASH\":",
        "\"TXHASH\" :",
        "\"txhash\":",
        "\"txhash\" :",
        "\"transaction_hash\":",
        "\"transaction_hash\" :",
        "\"TRANSACTION_HASH\":",
        "\"TRANSACTION_HASH\" :",
        "\"transaction-hash\":",
        "\"transaction-hash\" :",
        "\"TRANSACTION-HASH\":",
        "\"TRANSACTION-HASH\" :",
        "\"transaction hash\":",
        "\"transaction hash\" :",
        "\"TRANSACTION HASH\":",
        "\"TRANSACTION HASH\" :",
        "\"transactionHash\":",
        "\"transactionHash\" :",
        "\"TRANSACTIONHASH\":",
        "\"TRANSACTIONHASH\" :",
        "\"transactionhash\":",
        "\"transactionhash\" :",
        "'tx_hash':",
        "'tx_hash' :",
        "'TX_HASH':",
        "'TX_HASH' :",
        "'tx-hash':",
        "'tx-hash' :",
        "'TX-HASH':",
        "'TX-HASH' :",
        "'tx hash':",
        "'tx hash' :",
        "'TX HASH':",
        "'TX HASH' :",
        "'txHash':",
        "'txHash' :",
        "'TXHASH':",
        "'TXHASH' :",
        "'txhash':",
        "'txhash' :",
        "'transaction_hash':",
        "'transaction_hash' :",
        "'TRANSACTION_HASH':",
        "'TRANSACTION_HASH' :",
        "'transaction-hash':",
        "'transaction-hash' :",
        "'TRANSACTION-HASH':",
        "'TRANSACTION-HASH' :",
        "'transaction hash':",
        "'transaction hash' :",
        "'TRANSACTION HASH':",
        "'TRANSACTION HASH' :",
        "'transactionHash':",
        "'transactionHash' :",
        "'TRANSACTIONHASH':",
        "'TRANSACTIONHASH' :",
        "'transactionhash':",
        "'transactionhash' :",
    ];

    fn parse_hash_from_suffix(suffix: &str) -> Option<String> {
        let trimmed = suffix.trim_start();
        if trimmed.is_empty() {
            return None;
        }

        let mut candidate = trimmed;
        loop {
            let before = candidate;
            candidate = candidate.trim_start_matches(|ch: char| {
                ch.is_ascii_whitespace()
                    || ch.is_control()
                    || is_invisible_filler(ch)
                    || is_receipt_quote_wrapper(ch)
                    || is_receipt_bracket_wrapper(ch)
            });
            if let Some(rest) = candidate.strip_prefix('\\') {
                if rest.chars().next().is_some_and(is_receipt_quote_wrapper) {
                    candidate = rest;
                    continue;
                }
            }
            if candidate == before {
                break;
            }
        }
        if candidate.is_empty() {
            return None;
        }

        let candidate_end = candidate
            .char_indices()
            .find_map(|(idx, ch)| {
                let is_hash_char = ch.is_ascii_hexdigit()
                    || matches!(ch, 'x' | 'X')
                    || is_receipt_quote_wrapper(ch);
                (!is_hash_char).then_some(idx)
            })
            .unwrap_or(candidate.len());

        normalize_candidate_tx_hash(&candidate[..candidate_end])
    }

    let mut normalized_key_quotes = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek().copied().is_some_and(is_receipt_quote_wrapper) {
            continue;
        }
        if is_receipt_quote_wrapper(ch) {
            normalized_key_quotes.push('"');
        } else {
            normalized_key_quotes.push(ch);
        }
    }
    let normalized_delimiters = normalized_key_quotes
        .chars()
        .map(|ch| match ch {
            '：' => ':',
            '＝' => '=',
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => '-',
            other => other,
        })
        .collect::<String>();
    let mut normalized_whitespace = String::with_capacity(normalized_delimiters.len());
    let mut last_was_space = false;
    for ch in normalized_delimiters.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                normalized_whitespace.push(' ');
                last_was_space = true;
            }
        } else {
            normalized_whitespace.push(ch);
            last_was_space = false;
        }
    }
    let normalized_receipt_fillers = normalized_whitespace
        .chars()
        .filter(|ch| !ch.is_control() && !is_invisible_filler(*ch))
        .collect::<String>();

    for haystack in [
        text,
        normalized_key_quotes.as_str(),
        normalized_delimiters.as_str(),
        normalized_whitespace.as_str(),
        normalized_receipt_fillers.as_str(),
    ] {
        for prefix in PREFIXES {
            let mut remainder = haystack;
            while let Some(idx) = remainder.find(prefix) {
                let suffix = &remainder[idx + prefix.len()..];
                if let Some(parsed) = parse_hash_from_suffix(suffix) {
                    return Some(parsed);
                }
                let advance = suffix
                    .char_indices()
                    .nth(1)
                    .map(|(idx, _)| idx)
                    .unwrap_or(suffix.len());
                remainder = &suffix[advance..];
            }
        }
    }

    text.split_whitespace().find_map(|w| {
        PREFIXES
            .iter()
            .find_map(|prefix| w.strip_prefix(prefix))
            .and_then(normalize_candidate_tx_hash)
    })
}

fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED | RC_SLO_VIOLATION)
}

pub(crate) fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

pub(crate) fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

fn normalize_persisted_tx_hash(hash: Option<String>) -> Option<String> {
    hash.and_then(|value| {
        let mut trimmed = value
            .trim_matches(|c: char| c.is_whitespace() || c.is_control() || is_invisible_filler(c))
            .to_string();

        loop {
            let mut chars = trimmed.chars();
            let Some('\\') = chars.next() else {
                break;
            };
            let Some(start_quote) = chars.next() else {
                break;
            };
            if !is_receipt_quote_wrapper(start_quote) {
                break;
            }

            let mut rev_chars = trimmed.chars().rev();
            let Some(end_quote) = rev_chars.next() else {
                break;
            };
            let Some('\\') = rev_chars.next() else {
                break;
            };
            if !is_receipt_quote_wrapper(end_quote) {
                break;
            }

            let start = '\\'.len_utf8() + start_quote.len_utf8();
            let end = trimmed.len() - ('\\'.len_utf8() + end_quote.len_utf8());
            trimmed = trimmed[start..end].to_string();
        }

        if trimmed.is_empty() {
            None
        } else {
            parse_tx_hash(&trimmed)
                .or_else(|| normalize_candidate_tx_hash(&trimmed))
                .or(Some(trimmed))
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

fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    if base_ms == 0 {
        return 0;
    }

    let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    base_ms.saturating_mul(multiplier)
}

fn is_forbidden_shell_program(program: &str) -> bool {
    let leaf = Path::new(program)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    matches!(
        leaf.as_str(),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "cmd"
            | "powershell"
            | "pwsh"
    )
}

fn parse_command_spec(spec: &str) -> Result<(String, Vec<String>)> {
    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid command spec quoting"))?;
    if tokens.is_empty() {
        anyhow::bail!("empty command spec");
    }
    let program = tokens[0].clone();
    if is_forbidden_shell_program(&program) {
        anyhow::bail!("shell interpreter is forbidden in adapter command spec");
    }
    let args = tokens[1..].to_vec();
    Ok((program, args))
}

fn run_adapter_with_retry_inner<F, S>(
    max_retries: u32,
    backoff_ms: u64,
    mut exec_attempt: F,
    mut sleeper: S,
) -> Result<AdapterExecResult>
where
    F: FnMut() -> Result<Output>,
    S: FnMut(Duration),
{
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = exec_attempt()?;
        let rc = out.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tx_hash = parse_tx_hash(&stdout).or_else(|| parse_tx_hash(&stderr));

        if out.status.success() {
            return Ok(AdapterExecResult {
                ok: true,
                rc: RC_OK,
                tx_hash: tx_hash.or(last_tx_hash),
                terminal: true,
            });
        }

        last_rc = rc;
        if tx_hash.is_some() {
            last_tx_hash = tx_hash;
        }

        // deterministic terminal rejections (duplicate/nonce_rejected/slo_violation)
        // should not retry.
        if is_deterministic_rejection(rc) {
            return Ok(AdapterExecResult {
                ok: false,
                rc,
                tx_hash: last_tx_hash,
                terminal: true,
            });
        }

        if attempt < max_retries {
            let delay_ms = backoff_delay_ms(backoff_ms, attempt);
            if delay_ms > 0 {
                sleeper(Duration::from_millis(delay_ms));
            }
        }
    }

    Ok(AdapterExecResult {
        ok: false,
        rc: last_rc,
        tx_hash: last_tx_hash,
        terminal: false,
    })
}

pub(crate) fn run_adapter_with_retry(
    adapter_cmd: &str,
    action_args: &[String],
    max_retries: u32,
    backoff_ms: u64,
) -> Result<AdapterExecResult> {
    let (program, base_args) = parse_command_spec(adapter_cmd)?;
    run_adapter_with_retry_inner(
        max_retries,
        backoff_ms,
        || {
            Ok(ProcCommand::new(&program)
                .args(&base_args)
                .args(action_args)
                .output()?)
        },
        thread::sleep,
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct LlmAdapterResponse {
    pub(crate) output_text: String,
    #[serde(default)]
    pub(crate) provider_request_id: Option<String>,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) adapter: Option<String>,
    #[serde(default)]
    pub(crate) agent_protocol: Option<String>,
    #[serde(default)]
    pub(crate) compliance_profile: Option<String>,
}

fn truncate_for_error(raw: &str, max_chars: usize) -> String {
    let total = raw.chars().count();
    if total <= max_chars {
        return raw.to_string();
    }
    let prefix: String = raw.chars().take(max_chars).collect();
    format!("{}…(truncated, {} chars total)", prefix, total)
}

fn trim_config_numeric_value(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_whitespace()
            || c.is_control()
            || is_invisible_filler(c)
            || is_receipt_quote_wrapper(c)
    })
}

fn normalize_config_numeric_value(raw: &str) -> String {
    trim_config_numeric_value(raw)
        .chars()
        .filter(|ch| !ch.is_control() && !is_invisible_filler(*ch))
        .map(|ch| match ch {
            '０'..='９' => char::from_u32('0' as u32 + (ch as u32 - '０' as u32)).unwrap_or(ch),
            '＋' => '+',
            '－' | '−' => '-',
            other => other,
        })
        .collect()
}

fn parse_u32_with_min(raw: Option<&str>, default: u32, min: u32) -> u32 {
    raw.and_then(|s| normalize_config_numeric_value(s).parse::<u32>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn parse_u64_with_min(raw: Option<&str>, default: u64, min: u64) -> u64 {
    raw.and_then(|s| normalize_config_numeric_value(s).parse::<u64>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn resolve_u32(cli: Option<u32>, env_raw: Option<&str>, default: u32, min: u32) -> u32 {
    cli.filter(|v| *v >= min)
        .unwrap_or_else(|| parse_u32_with_min(env_raw, default, min))
}

fn resolve_u64(cli: Option<u64>, env_raw: Option<&str>, default: u64, min: u64) -> u64 {
    cli.filter(|v| *v >= min)
        .unwrap_or_else(|| parse_u64_with_min(env_raw, default, min))
}

pub(crate) fn resolve_tx_retry_policy_from_sources(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
    env_max_retries_raw: Option<&str>,
    env_backoff_ms_raw: Option<&str>,
) -> RetryPolicy {
    RetryPolicy {
        max_retries: resolve_u32(
            max_retries_cli,
            env_max_retries_raw,
            DEFAULT_TX_ADAPTER_MAX_RETRIES,
            0,
        ),
        backoff_ms: resolve_u64(
            backoff_ms_cli,
            env_backoff_ms_raw,
            DEFAULT_TX_ADAPTER_BACKOFF_MS,
            0,
        ),
    }
}

pub(crate) fn resolve_tx_retry_policy(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
) -> RetryPolicy {
    resolve_tx_retry_policy_from_sources(
        max_retries_cli,
        backoff_ms_cli,
        env::var(TX_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
        env::var(TX_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
    )
}

pub(crate) fn resolve_llm_adapter_policy(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
    timeout_ms_cli: Option<u64>,
) -> LlmAdapterPolicy {
    LlmAdapterPolicy {
        retry: RetryPolicy {
            max_retries: resolve_u32(
                max_retries_cli,
                env::var(LLM_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
                DEFAULT_LLM_ADAPTER_MAX_RETRIES,
                0,
            ),
            backoff_ms: resolve_u64(
                backoff_ms_cli,
                env::var(LLM_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
                DEFAULT_LLM_ADAPTER_BACKOFF_MS,
                0,
            ),
        },
        timeout_ms: resolve_u64(
            timeout_ms_cli,
            env::var(LLM_ADAPTER_TIMEOUT_ENV).ok().as_deref(),
            DEFAULT_LLM_ADAPTER_TIMEOUT_MS,
            1,
        ),
    }
}

fn run_command_with_timeout(
    program: &str,
    base_args: &[String],
    extra_args: &[String],
    timeout: Duration,
) -> Result<Output> {
    let mut child = ProcCommand::new(program)
        .args(base_args)
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    match child.wait_timeout(timeout)? {
        Some(_) => Ok(child.wait_with_output()?),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("llm adapter timeout after {}ms", timeout.as_millis());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorKind {
    Retriable,
    NonRetriable,
}

#[derive(Debug, Clone)]
pub(crate) struct AdapterError {
    pub(crate) kind: AdapterErrorKind,
    pub(crate) context: String,
}

fn exp_backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    backoff_delay_ms(base_ms, attempt)
}

fn run_llm_adapter_once(
    adapter_cmd: &str,
    prompt: &str,
    timeout: Duration,
    proof_adapter: &dyn ProofAdapter,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    let (program, base_args) = parse_command_spec(adapter_cmd).map_err(|e| AdapterError {
        kind: AdapterErrorKind::NonRetriable,
        context: format!("invalid llm adapter command: {e}"),
    })?;
    let prompt_arg = vec![prompt.to_string()];
    let out =
        run_command_with_timeout(&program, &base_args, &prompt_arg, timeout).map_err(|e| {
            AdapterError {
                kind: AdapterErrorKind::Retriable,
                context: e.to_string(),
            }
        })?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(AdapterError {
            kind: AdapterErrorKind::Retriable,
            context: format!(
                "llm adapter failed rc={:?} stderr={}",
                out.status.code(),
                truncate_for_error(&stderr, 512)
            ),
        });
    }
    proof_adapter
        .parse_response(&stdout)
        .map_err(|e| AdapterError {
            kind: AdapterErrorKind::NonRetriable,
            context: format!(
                "llm adapter invalid payload: {} raw={}",
                e,
                truncate_for_error(&stdout, 512)
            ),
        })
}

fn run_llm_adapter_with_retry_inner<F, S>(
    max_retries: u32,
    backoff_ms: u64,
    mut op: F,
    mut sleeper: S,
) -> std::result::Result<LlmAdapterResponse, AdapterError>
where
    F: FnMut() -> std::result::Result<LlmAdapterResponse, AdapterError>,
    S: FnMut(Duration),
{
    let mut last_error: Option<AdapterError> = None;
    for attempt in 0..=max_retries {
        match op() {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                let should_retry = err.kind == AdapterErrorKind::Retriable && attempt < max_retries;
                last_error = Some(err);
                if should_retry {
                    let delay_ms = exp_backoff_delay_ms(backoff_ms, attempt);
                    if delay_ms > 0 {
                        sleeper(Duration::from_millis(delay_ms));
                    }
                    continue;
                }
                break;
            }
        }
    }

    Err(last_error.unwrap_or(AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: "llm adapter failed: unknown error".to_string(),
    }))
}

pub(crate) fn run_llm_adapter_with_retry(
    adapter_cmd: &str,
    prompt: &str,
    retry: RetryPolicy,
    timeout: Duration,
    proof_adapter: &dyn ProofAdapter,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    run_llm_adapter_with_retry_inner(
        retry.max_retries,
        retry.backoff_ms,
        || run_llm_adapter_once(adapter_cmd, prompt, timeout, proof_adapter),
        thread::sleep,
    )
}

fn is_invisible_filler(c: char) -> bool {
    matches!(
        c,
        '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
            | '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZERO WIDTH NON-JOINER
            | '\u{200D}' // ZERO WIDTH JOINER
            | '\u{200E}' // LEFT-TO-RIGHT MARK
            | '\u{200F}' // RIGHT-TO-LEFT MARK
            | '\u{061C}' // ARABIC LETTER MARK (bidi/invisible)
            | '\u{2060}' // WORD JOINER
            | '\u{2061}' // FUNCTION APPLICATION (invisible operator)
            | '\u{2062}' // INVISIBLE TIMES
            | '\u{2063}' // INVISIBLE SEPARATOR
            | '\u{2064}' // INVISIBLE PLUS
            | '\u{2066}' // LEFT-TO-RIGHT ISOLATE
            | '\u{2067}' // RIGHT-TO-LEFT ISOLATE
            | '\u{2068}' // FIRST STRONG ISOLATE
            | '\u{2069}' // POP DIRECTIONAL ISOLATE
            | '\u{00AD}' // SOFT HYPHEN
            | '\u{034F}' // COMBINING GRAPHEME JOINER (non-rendering)
            | '\u{180E}' // MONGOLIAN VOWEL SEPARATOR (historically zero-width)
            | '\u{FE0E}' // VARIATION SELECTOR-15 (text presentation)
            | '\u{FE0F}' // VARIATION SELECTOR-16 (emoji presentation)
    )
}

fn verify_model_output(output: &str, max_chars: usize) -> (&'static str, &'static str) {
    let trimmed = output.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .any(|c| !c.is_whitespace() && !c.is_control() && !is_invisible_filler(c))
    {
        return ("rejected", "empty_output");
    }

    let normalized_char_count = trimmed
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_filler(*c))
        .count();
    if normalized_char_count > max_chars {
        return ("rejected", "output_too_long");
    }
    ("accepted", "ok")
}

pub(crate) fn normalized_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn trim_boundary_audit_fillers(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || c.is_control() || is_invisible_filler(c))
}

pub(crate) fn normalized_provider_request_id(value: Option<&str>) -> Option<String> {
    let normalized =
        trim_boundary_audit_fillers(normalized_optional_field(value)?.as_str()).to_string();
    if normalized.is_empty() {
        return None;
    }
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    let starts_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_alphanumeric() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    if is_allowed && starts_and_ends_alnum && normalized.len() <= 128 {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_provenance_label(value: Option<&str>, max_len: usize) -> Option<String> {
    let normalized = normalized_optional_field(value)?;
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii() || c.is_ascii_control());
    if !has_disallowed_chars && normalized.len() <= max_len {
        Some(normalized)
    } else {
        None
    }
}

pub(crate) fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars || normalized.len() > 128 {
        return None;
    }

    let alias_key: String = normalized
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let alias_key = alias_key.trim_end_matches(|c: char| c.is_ascii_digit());
    match alias_key {
        "mcp"
        | "mcpv"
        | "mcpv1"
        | "mcpv2"
        | "mcpjsonrpc"
        | "mcpjsonrpcv"
        | "mcpjsonrpcv1"
        | "mcpjsonrpcv2"
        | "mcpoverjsonrpc"
        | "mcpoverjsonrpcv"
        | "mcpoverjsonrpcv1"
        | "mcpoverjsonrpcv2"
        | "mcpstdio"
        | "mcpstdiov"
        | "mcpstdiov1"
        | "mcpstdiov2"
        | "mcpoverstdio"
        | "mcpoverstdiov"
        | "mcpoverstdiov1"
        | "mcpoverstdiov2"
        | "mcpsse"
        | "mcpssev"
        | "mcpssev1"
        | "mcpssev2"
        | "mcpoversse"
        | "mcpoverssev"
        | "mcpoverssev1"
        | "mcpoverssev2"
        | "modelcontextprotocol"
        | "modelcontextprotocolv"
        | "modelcontextprotocolv1"
        | "modelcontextprotocolv2"
        | "modelcontextprotocoljsonrpc"
        | "modelcontextprotocoljsonrpcv"
        | "modelcontextprotocoljsonrpcv1"
        | "modelcontextprotocoljsonrpcv2"
        | "modelcontextprotocolstdio"
        | "modelcontextprotocolstdiov"
        | "modelcontextprotocolstdiov1"
        | "modelcontextprotocolstdiov2"
        | "modelcontextprotocolsse"
        | "modelcontextprotocolssev"
        | "modelcontextprotocolssev1"
        | "modelcontextprotocolssev2"
        | "mcpstreamablehttp"
        | "mcpstreamablehttpv"
        | "mcpstreamablehttpv1"
        | "mcpstreamablehttpv2"
        | "mcpoverstreamablehttp"
        | "mcpoverstreamablehttpv"
        | "mcpoverstreamablehttpv1"
        | "mcpoverstreamablehttpv2"
        | "modelcontextprotocolstreamablehttp"
        | "modelcontextprotocolstreamablehttpv"
        | "modelcontextprotocolstreamablehttpv1"
        | "modelcontextprotocolstreamablehttpv2"
        | "modelcontextprotocoloverstreamablehttp"
        | "modelcontextprotocoloverstreamablehttpv"
        | "modelcontextprotocoloverstreamablehttpv1"
        | "modelcontextprotocoloverstreamablehttpv2"
        | "mcphttp"
        | "mcphttpv"
        | "mcpoverhttp"
        | "mcpoverhttpv"
        | "modelcontextprotocolhttp"
        | "modelcontextprotocolhttpv"
        | "modelcontextprotocoloverhttp"
        | "modelcontextprotocoloverhttpv"
        | "openaimcp"
        | "openaimcpprotocol"
        | "openaimodelcontextprotocol"
        | "openaimodelcontextprotocolv"
        | "openaimodelcontextprotocolv1"
        | "openaimodelcontextprotocolv2"
        | "openaimcphttp"
        | "openaimcphttpv"
        | "openaimcpoverhttp"
        | "openaimcpoverhttpv"
        | "openaimcpstreamablehttp"
        | "openaimcpstreamablehttpv"
        | "openaimcpoverstreamablehttp"
        | "openaimcpoverstreamablehttpv"
        | "openaimcpsse"
        | "openaimcpssev"
        | "openaimcpoversse"
        | "openaimcpoverssev"
        | "openaimodelcontextprotocolstreamablehttp"
        | "openaimodelcontextprotocolstreamablehttpv"
        | "openaimodelcontextprotocoloverstreamablehttp"
        | "openaimodelcontextprotocoloverstreamablehttpv"
        | "openaimodelcontextprotocolsse"
        | "openaimodelcontextprotocolssev"
        | "openaimodelcontextprotocoloversse"
        | "openaimodelcontextprotocoloverssev"
        | "mcpwebsocket"
        | "mcpwebsocketv"
        | "mcpwebsockets"
        | "mcpwebsocketsv"
        | "mcpws"
        | "mcpwsv"
        | "mcpoverwebsocket"
        | "mcpoverwebsocketv"
        | "mcpoverwebsockets"
        | "mcpoverwebsocketsv"
        | "mcpoverws"
        | "mcpoverwsv"
        | "modelcontextprotocolwebsocket"
        | "modelcontextprotocolwebsocketv"
        | "modelcontextprotocolwebsockets"
        | "modelcontextprotocolwebsocketsv"
        | "modelcontextprotocoloverwebsocket"
        | "modelcontextprotocoloverwebsocketv"
        | "modelcontextprotocoloverwebsockets"
        | "modelcontextprotocoloverwebsocketsv"
        | "openaimcpwebsocket"
        | "openaimcpwebsocketv"
        | "openaimcpwebsockets"
        | "openaimcpwebsocketsv"
        | "openaimcpoverwebsocket"
        | "openaimcpoverwebsocketv"
        | "openaimcpoverwebsockets"
        | "openaimcpoverwebsocketsv"
        | "openaimodelcontextprotocolwebsocket"
        | "openaimodelcontextprotocolwebsocketv"
        | "openaimodelcontextprotocolwebsockets"
        | "openaimodelcontextprotocolwebsocketsv"
        | "openaimodelcontextprotocoloverwebsocket"
        | "openaimodelcontextprotocoloverwebsocketv"
        | "openaimodelcontextprotocoloverwebsockets"
        | "openaimodelcontextprotocoloverwebsocketsv"
        | "anthropicmcp"
        | "anthropicmcpprotocol"
        | "anthropicmodelcontextprotocol"
        | "anthropicmodelcontextprotocolv"
        | "anthropicmodelcontextprotocolv1"
        | "anthropicmodelcontextprotocolv2"
        | "anthropicmcphttp"
        | "anthropicmcphttpv"
        | "anthropicmcpoverhttp"
        | "anthropicmcpoverhttpv"
        | "anthropicmcpstreamablehttp"
        | "anthropicmcpstreamablehttpv"
        | "anthropicmcpoverstreamablehttp"
        | "anthropicmcpoverstreamablehttpv"
        | "anthropicmcpsse"
        | "anthropicmcpssev"
        | "anthropicmcpoversse"
        | "anthropicmcpoverssev"
        | "anthropicmodelcontextprotocolhttp"
        | "anthropicmodelcontextprotocolhttpv"
        | "anthropicmodelcontextprotocoloverhttp"
        | "anthropicmodelcontextprotocoloverhttpv"
        | "anthropicmodelcontextprotocolstreamablehttp"
        | "anthropicmodelcontextprotocolstreamablehttpv"
        | "anthropicmodelcontextprotocoloverstreamablehttp"
        | "anthropicmodelcontextprotocoloverstreamablehttpv"
        | "anthropicmodelcontextprotocolsse"
        | "anthropicmodelcontextprotocolssev"
        | "anthropicmodelcontextprotocoloversse"
        | "anthropicmodelcontextprotocoloverssev"
        | "anthropicmcpwebsocket"
        | "anthropicmcpwebsocketv"
        | "anthropicmcpwebsockets"
        | "anthropicmcpwebsocketsv"
        | "anthropicmcpoverwebsocket"
        | "anthropicmcpoverwebsocketv"
        | "anthropicmcpoverwebsockets"
        | "anthropicmcpoverwebsocketsv"
        | "anthropicmodelcontextprotocolwebsocket"
        | "anthropicmodelcontextprotocolwebsocketv"
        | "anthropicmodelcontextprotocolwebsockets"
        | "anthropicmodelcontextprotocolwebsocketsv"
        | "anthropicmodelcontextprotocoloverwebsocket"
        | "anthropicmodelcontextprotocoloverwebsocketv"
        | "anthropicmodelcontextprotocoloverwebsockets"
        | "anthropicmodelcontextprotocoloverwebsocketsv" => Some("mcp".to_string()),
        "a2a"
        | "a2av"
        | "a2av1"
        | "a2av2"
        | "a2ajsonrpc"
        | "a2ajsonrpcv"
        | "a2ajsonrpcv1"
        | "a2ajsonrpcv2"
        | "a2aoverjsonrpc"
        | "a2aoverjsonrpcv"
        | "a2aoverjsonrpcv1"
        | "a2aoverjsonrpcv2"
        | "a2astdio"
        | "a2astdiov"
        | "a2astdiov1"
        | "a2astdiov2"
        | "a2aoverstdio"
        | "a2aoverstdiov"
        | "a2aoverstdiov1"
        | "a2aoverstdiov2"
        | "a2asse"
        | "a2assev"
        | "a2assev1"
        | "a2assev2"
        | "a2aoversse"
        | "a2aoverssev"
        | "a2aoverssev1"
        | "a2aoverssev2"
        | "a2aprotocol"
        | "agent2agent"
        | "agenttoagent"
        | "agent2agentprotocol"
        | "agenttoagentprotocol"
        | "agent2agentprotocolv"
        | "agent2agentprotocolv1"
        | "agent2agentprotocolv2"
        | "agenttoagentprotocolv"
        | "agenttoagentprotocolv1"
        | "agenttoagentprotocolv2"
        | "agent2agentv"
        | "agent2agentv1"
        | "agent2agentv2"
        | "agenttoagentv"
        | "agenttoagentv1"
        | "agenttoagentv2"
        | "agent2agentjsonrpc"
        | "agent2agentjsonrpcv"
        | "agent2agentjsonrpcv1"
        | "agent2agentjsonrpcv2"
        | "agent2agentstdio"
        | "agent2agentstdiov"
        | "agent2agentstdiov1"
        | "agent2agentstdiov2"
        | "agenttoagentjsonrpc"
        | "agenttoagentjsonrpcv"
        | "agenttoagentjsonrpcv1"
        | "agenttoagentjsonrpcv2"
        | "agenttoagentstdio"
        | "agenttoagentstdiov"
        | "agenttoagentstdiov1"
        | "agenttoagentstdiov2"
        | "agent2agentprotocoljsonrpc"
        | "agent2agentprotocoljsonrpcv"
        | "agent2agentprotocoljsonrpcv1"
        | "agent2agentprotocoljsonrpcv2"
        | "agent2agentprotocolstdio"
        | "agent2agentprotocolstdiov"
        | "agent2agentprotocolstdiov1"
        | "agent2agentprotocolstdiov2"
        | "agenttoagentprotocoljsonrpc"
        | "agenttoagentprotocoljsonrpcv"
        | "agenttoagentprotocoljsonrpcv1"
        | "agenttoagentprotocoljsonrpcv2"
        | "agenttoagentprotocolstdio"
        | "agenttoagentprotocolstdiov"
        | "agenttoagentprotocolstdiov1"
        | "agenttoagentprotocolstdiov2"
        | "a2astreamablehttp"
        | "a2astreamablehttpv"
        | "a2astreamablehttpv1"
        | "a2astreamablehttpv2"
        | "a2aoverstreamablehttp"
        | "a2aoverstreamablehttpv"
        | "a2aoverstreamablehttpv1"
        | "a2aoverstreamablehttpv2"
        | "a2ahttp"
        | "a2ahttpv"
        | "a2aoverhttp"
        | "a2aoverhttpv"
        | "a2awebsocket"
        | "a2awebsocketv"
        | "a2awebsockets"
        | "a2awebsocketsv"
        | "a2aws"
        | "a2awsv"
        | "a2aoverwebsocket"
        | "a2aoverwebsocketv"
        | "a2aoverwebsockets"
        | "a2aoverwebsocketsv"
        | "a2aoverws"
        | "a2aoverwsv"
        | "agent2agenthttp"
        | "agent2agenthttpv"
        | "agenttoagenthttp"
        | "agenttoagenthttpv"
        | "agent2agentprotocolhttp"
        | "agent2agentprotocolhttpv"
        | "agenttoagentprotocolhttp"
        | "agenttoagentprotocolhttpv"
        | "agent2agentwebsocket"
        | "agent2agentwebsocketv"
        | "agent2agentwebsockets"
        | "agent2agentwebsocketsv"
        | "agent2agentoverwebsocket"
        | "agent2agentoverwebsocketv"
        | "agent2agentoverwebsockets"
        | "agent2agentoverwebsocketsv"
        | "agenttoagentwebsocket"
        | "agenttoagentwebsocketv"
        | "agenttoagentwebsockets"
        | "agenttoagentwebsocketsv"
        | "agenttoagentoverwebsocket"
        | "agenttoagentoverwebsocketv"
        | "agenttoagentoverwebsockets"
        | "agenttoagentoverwebsocketsv"
        | "agent2agentprotocolwebsocket"
        | "agent2agentprotocolwebsocketv"
        | "agent2agentprotocolwebsockets"
        | "agent2agentprotocolwebsocketsv"
        | "agent2agentprotocoloverwebsocket"
        | "agent2agentprotocoloverwebsocketv"
        | "agent2agentprotocoloverwebsockets"
        | "agent2agentprotocoloverwebsocketsv"
        | "agenttoagentprotocolwebsocket"
        | "agenttoagentprotocolwebsocketv"
        | "agenttoagentprotocolwebsockets"
        | "agenttoagentprotocolwebsocketsv"
        | "agenttoagentprotocoloverwebsocket"
        | "agenttoagentprotocoloverwebsocketv"
        | "agenttoagentprotocoloverwebsockets"
        | "agenttoagentprotocoloverwebsocketsv"
        | "agent2agentstreamablehttp"
        | "agent2agentstreamablehttpv"
        | "agent2agentstreamablehttpv1"
        | "agent2agentstreamablehttpv2"
        | "agenttoagentstreamablehttp"
        | "agenttoagentstreamablehttpv"
        | "agenttoagentstreamablehttpv1"
        | "agenttoagentstreamablehttpv2"
        | "googlea2a"
        | "googlea2av"
        | "googlea2ajsonrpc"
        | "googlea2ajsonrpcv"
        | "googlea2aoverjsonrpc"
        | "googlea2aoverjsonrpcv"
        | "googlea2aprotocol"
        | "googlea2ahttp"
        | "googlea2ahttpv"
        | "googlea2aoverhttp"
        | "googlea2aoverhttpv"
        | "googleagent2agent"
        | "googleagent2agentprotocol"
        | "googleagent2agentv"
        | "googleagent2agentprotocolv"
        | "googleagent2agentjsonrpc"
        | "googleagent2agentjsonrpcv"
        | "googleagent2agentstreamablehttp"
        | "googleagent2agentstreamablehttpv"
        | "googleagent2agentoverstreamablehttp"
        | "googleagent2agentoverstreamablehttpv"
        | "googleagenttoagent"
        | "googleagenttoagentprotocol"
        | "googleagenttoagentv"
        | "googleagenttoagentprotocolv"
        | "googleagenttoagentjsonrpc"
        | "googleagenttoagentjsonrpcv"
        | "googleagenttoagentstreamablehttp"
        | "googleagenttoagentstreamablehttpv"
        | "googleagenttoagentoverstreamablehttp"
        | "googleagenttoagentoverstreamablehttpv"
        | "googleagent2agenthttp"
        | "googleagent2agenthttpv"
        | "googleagent2agentoverhttp"
        | "googleagent2agentoverhttpv"
        | "googleagent2agentwebsocket"
        | "googleagent2agentwebsocketv"
        | "googleagent2agentwebsockets"
        | "googleagent2agentwebsocketsv"
        | "googleagent2agentoverwebsocket"
        | "googleagent2agentoverwebsocketv"
        | "googleagent2agentoverwebsockets"
        | "googleagent2agentoverwebsocketsv"
        | "googleagenttoagenthttp"
        | "googleagenttoagenthttpv"
        | "googleagenttoagentoverhttp"
        | "googleagenttoagentoverhttpv"
        | "googleagenttoagentwebsocket"
        | "googleagenttoagentwebsocketv"
        | "googleagenttoagentwebsockets"
        | "googleagenttoagentwebsocketsv"
        | "googleagenttoagentoverwebsocket"
        | "googleagenttoagentoverwebsocketv"
        | "googleagenttoagentoverwebsockets"
        | "googleagenttoagentoverwebsocketsv" => Some("a2a".to_string()),
        _ => None,
    }
}

pub(crate) fn normalized_compliance_profile(value: Option<&str>) -> Option<String> {
    let raw = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = raw
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars {
        return None;
    }

    let normalized: String = raw
        .chars()
        .map(|c| if c.is_ascii_whitespace() { '-' } else { c })
        .collect();
    let is_allowed = normalized.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/' | '\\')
    });
    let starts_with_alpha_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_lowercase() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    let has_adjacent_separators = normalized
        .chars()
        .fold((false, false), |(found, prev_sep), c| {
            let is_sep = matches!(c, '-' | '_' | '.' | '/' | '\\');
            (found || (prev_sep && is_sep), is_sep)
        })
        .0;
    let has_alpha = normalized.chars().any(|c| c.is_ascii_lowercase());
    let has_separator = normalized
        .chars()
        .any(|c| matches!(c, '-' | '_' | '.' | '/' | '\\'));
    if is_allowed
        && starts_with_alpha_and_ends_alnum
        && !has_adjacent_separators
        && normalized.len() <= 64
        && has_alpha
        && has_separator
    {
        Some(
            normalized
                .chars()
                .map(|c| {
                    if matches!(c, '_' | '.' | '/' | '\\') {
                        '-'
                    } else {
                        c
                    }
                })
                .collect(),
        )
    } else {
        None
    }
}

pub(crate) fn attach_llm_provenance(rec: &mut MessageIngressRecord, llm: &LlmAdapterResponse) {
    rec.provider_request_id = normalized_provider_request_id(llm.provider_request_id.as_deref());

    let provider = normalized_provenance_label(llm.provider.as_deref(), 64);
    let model = normalized_provenance_label(llm.model.as_deref(), 128);
    let adapter = normalized_provenance_label(llm.adapter.as_deref(), 64);
    let agent_protocol = normalized_agent_protocol(llm.agent_protocol.as_deref());
    let compliance_profile = normalized_compliance_profile(llm.compliance_profile.as_deref());

    let has_v1_fields = provider.is_some() || model.is_some() || adapter.is_some();
    let has_v2_fields = agent_protocol.is_some() || compliance_profile.is_some();
    let has_structured_provenance = has_v1_fields || has_v2_fields;

    rec.provenance_schema_version = if has_v2_fields {
        Some("llm.v2".to_string())
    } else if has_v1_fields {
        Some("llm.v1".to_string())
    } else {
        None
    };

    rec.llm_provenance = has_structured_provenance.then(|| LlmProvenanceRecord {
        provider,
        model,
        adapter,
        agent_protocol,
        compliance_profile,
    });
}

fn collapse_contract_match_delimiters(value: &str) -> String {
    value
        .chars()
        .filter_map(|ch| match ch {
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{2063}' | '\u{feff}' => None,
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => Some('-'),
            other => Some(other),
        })
        .collect()
}

fn context_matches_token(context: &str, token: &str) -> bool {
    fn normalize_for_contract_match(value: &str) -> String {
        let lowered = collapse_contract_match_delimiters(value).to_ascii_lowercase();
        let mut out = String::with_capacity(lowered.len());
        let mut prev_space = false;
        for ch in lowered.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch);
                prev_space = false;
            } else if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        }
        out.trim().to_string()
    }

    let normalized_context = collapse_contract_match_delimiters(context).to_ascii_lowercase();
    let normalized_token = collapse_contract_match_delimiters(token).to_ascii_lowercase();
    let context_with_spaces = normalized_context.replace(['-', '_'], " ");
    let token_with_spaces = normalized_token.replace(['-', '_'], " ");
    let normalized_context_relaxed = normalize_for_contract_match(context);
    let normalized_token_relaxed = normalize_for_contract_match(token);
    let normalized_context_compact = normalized_context_relaxed.replace(' ', "");
    let normalized_token_compact = normalized_token_relaxed.replace(' ', "");

    normalized_context.contains(&normalized_token)
        || normalized_context.contains(&normalized_token.replace('-', "_"))
        || normalized_context.contains(&normalized_token.replace('_', "-"))
        || context_with_spaces.contains(&token_with_spaces)
        || (!normalized_token_relaxed.is_empty()
            && normalized_context_relaxed.contains(&normalized_token_relaxed))
        || (!normalized_token_compact.is_empty()
            && normalized_context_compact.contains(&normalized_token_compact))
}

pub(crate) fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
    if context_matches_token(&err.context, "proof-missing")
        || context_matches_token(&err.context, "missing-provider-request-id")
    {
        return ("ERR_M2V2_PROOF_MISSING", "proof_missing");
    }
    if context_matches_token(&err.context, "proof-invalid")
        || context_matches_token(&err.context, "missing-adapter-label")
        || context_matches_token(&err.context, "no-json-line")
        || context_matches_token(&err.context, "invalid-json")
    {
        return ("ERR_M2V2_PROOF_INVALID", "proof_invalid");
    }
    if context_matches_token(&err.context, "settlement-degraded") {
        return ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded");
    }
    if context_matches_token(&err.context, "proof-late")
        || context_matches_token(&err.context, "timeout")
    {
        return ("ERR_M2V2_PROOF_LATE", "proof_late");
    }

    match err.kind {
        AdapterErrorKind::Retriable => ("adapter_error", "retry_exhausted"),
        AdapterErrorKind::NonRetriable => ("adapter_error", "non_retriable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReputationSignal {
    Accepted,
    VerifierRejected,
    AdapterRetryExhausted,
    AdapterNonRetriable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReputationImpact {
    pub(crate) label: &'static str,
    pub(crate) delta: i32,
    pub(crate) tier: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReputationSurface {
    pub(crate) label: &'static str,
    pub(crate) delta: i32,
    pub(crate) tier: u8,
    pub(crate) weight_bps: u16,
    pub(crate) score_bps: i32,
    pub(crate) rank_ordinal: u8,
}

pub(crate) const CANONICAL_REPUTATION_SIGNAL_ORDER: [ReputationSignal; 4] = [
    ReputationSignal::Accepted,
    ReputationSignal::AdapterRetryExhausted,
    ReputationSignal::VerifierRejected,
    ReputationSignal::AdapterNonRetriable,
];

pub(crate) const CANONICAL_REPUTATION_IMPACTS: [(ReputationSignal, ReputationImpact); 4] = [
    (
        ReputationSignal::Accepted,
        ReputationImpact {
            label: "accepted",
            delta: 3,
            tier: 3,
        },
    ),
    (
        ReputationSignal::AdapterRetryExhausted,
        ReputationImpact {
            label: "adapter_retry_exhausted",
            delta: -1,
            tier: 2,
        },
    ),
    (
        ReputationSignal::VerifierRejected,
        ReputationImpact {
            label: "verifier_rejected",
            delta: -2,
            tier: 1,
        },
    ),
    (
        ReputationSignal::AdapterNonRetriable,
        ReputationImpact {
            label: "adapter_non_retriable",
            delta: -3,
            tier: 0,
        },
    ),
];

pub(crate) fn reputation_impact(signal: ReputationSignal) -> ReputationImpact {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(candidate, impact)| (*candidate == signal).then_some(*impact))
        .expect("canonical reputation mapping must cover all reputation signals")
}

pub(crate) fn reputation_score_impact(signal: ReputationSignal) -> (&'static str, i32) {
    let impact = reputation_impact(signal);
    (impact.label, impact.delta)
}

pub(crate) fn reputation_signal_from_label(label: &str) -> Option<ReputationSignal> {
    let normalized = label.trim();
    if normalized.is_empty() {
        return None;
    }

    CANONICAL_REPUTATION_IMPACTS.iter().find_map(|(signal, impact)| {
        context_matches_token(normalized, impact.label).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_label(label: &str) -> Option<ReputationImpact> {
    reputation_signal_from_label(label).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_score_impact(
    label: &str,
    delta: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| {
            (impact.label == label && impact.delta == delta).then_some(*signal)
        })
}

pub(crate) fn reputation_impact_from_score_impact(
    label: &str,
    delta: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_score_impact(label, delta).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_delta(delta: i32) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| (impact.delta == delta).then_some(*signal))
}

pub(crate) fn reputation_impact_from_delta(delta: i32) -> Option<ReputationImpact> {
    reputation_signal_from_delta(delta).map(reputation_impact)
}

pub(crate) fn reputation_signal_from_tier(tier: u8) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_IMPACTS
        .iter()
        .find_map(|(signal, impact)| (impact.tier == tier).then_some(*signal))
}

pub(crate) fn reputation_impact_from_tier(tier: u8) -> Option<ReputationImpact> {
    reputation_signal_from_tier(tier).map(reputation_impact)
}

pub(crate) fn reputation_delta(signal: ReputationSignal) -> i32 {
    reputation_impact(signal).delta
}

pub(crate) fn reputation_tier(signal: ReputationSignal) -> u8 {
    reputation_impact(signal).tier
}

pub(crate) fn reputation_rank_ordinal(signal: ReputationSignal) -> u8 {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .position(|candidate| *candidate == signal)
        .map(|idx| idx as u8)
        .expect("canonical reputation signal order must cover all reputation signals")
}

pub(crate) fn reputation_signal_from_rank_ordinal(rank_ordinal: u8) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .get(rank_ordinal as usize)
        .copied()
}

pub(crate) fn reputation_impact_from_rank_ordinal(rank_ordinal: u8) -> Option<ReputationImpact> {
    reputation_signal_from_rank_ordinal(rank_ordinal).map(reputation_impact)
}

pub(crate) fn reputation_weight_bps(signal: ReputationSignal) -> u16 {
    let impact = reputation_impact(signal);
    let max_tier = CANONICAL_REPUTATION_IMPACTS
        .first()
        .map(|(_, impact)| impact.tier)
        .unwrap_or(0);
    if max_tier == 0 {
        return 10_000;
    }

    ((u32::from(impact.tier) * 10_000) / u32::from(max_tier)) as u16
}

pub(crate) fn reputation_score_bps(signal: ReputationSignal) -> i32 {
    let impact = reputation_impact(signal);
    let max_abs_delta = CANONICAL_REPUTATION_IMPACTS
        .iter()
        .map(|(_, impact)| impact.delta.abs())
        .max()
        .unwrap_or(0);
    if max_abs_delta == 0 {
        return 0;
    }

    (impact.delta * 10_000) / max_abs_delta
}

pub(crate) fn reputation_gap_bps_from_best(signal: ReputationSignal) -> i32 {
    let best_score_bps = CANONICAL_REPUTATION_SIGNAL_ORDER
        .first()
        .copied()
        .map(reputation_score_bps)
        .unwrap_or(0);
    best_score_bps - reputation_score_bps(signal)
}

pub(crate) fn reputation_signal_from_gap_bps_from_best(
    gap_bps_from_best: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_best(*signal) == gap_bps_from_best).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_gap_bps_from_best(
    gap_bps_from_best: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_bps_from_best(gap_bps_from_best).map(reputation_impact)
}

pub(crate) fn reputation_gap_bps_from_worst(signal: ReputationSignal) -> i32 {
    let worst_score_bps = CANONICAL_REPUTATION_SIGNAL_ORDER
        .last()
        .copied()
        .map(reputation_score_bps)
        .unwrap_or(0);
    reputation_score_bps(signal) - worst_score_bps
}

pub(crate) fn reputation_signal_from_gap_bps_from_worst(
    gap_bps_from_worst: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_worst(*signal) == gap_bps_from_worst).then_some(*signal)
    })
}

pub(crate) fn reputation_impact_from_gap_bps_from_worst(
    gap_bps_from_worst: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_bps_from_worst(gap_bps_from_worst).map(reputation_impact)
}

#[cfg(test)]
pub(crate) fn reputation_signal_from_gap_pair(
    gap_bps_from_best: i32,
    gap_bps_from_worst: i32,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        (reputation_gap_bps_from_best(*signal) == gap_bps_from_best
            && reputation_gap_bps_from_worst(*signal) == gap_bps_from_worst)
            .then_some(*signal)
    })
}

#[cfg(test)]
pub(crate) fn reputation_impact_from_gap_pair(
    gap_bps_from_best: i32,
    gap_bps_from_worst: i32,
) -> Option<ReputationImpact> {
    reputation_signal_from_gap_pair(gap_bps_from_best, gap_bps_from_worst).map(reputation_impact)
}

#[cfg(test)]
pub(crate) fn reputation_signal_from_score_bps(score_bps: i32) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .find_map(|signal| (reputation_score_bps(*signal) == score_bps).then_some(*signal))
}

#[cfg(test)]
pub(crate) fn reputation_impact_from_score_bps(score_bps: i32) -> Option<ReputationImpact> {
    reputation_signal_from_score_bps(score_bps).map(reputation_impact)
}

pub(crate) fn reputation_surface(signal: ReputationSignal) -> ReputationSurface {
    let impact = reputation_impact(signal);
    ReputationSurface {
        label: impact.label,
        delta: impact.delta,
        tier: impact.tier,
        weight_bps: reputation_weight_bps(signal),
        score_bps: reputation_score_bps(signal),
        rank_ordinal: reputation_rank_ordinal(signal),
    }
}

#[cfg(test)]
pub(crate) fn canonical_reputation_surfaces() -> [ReputationSurface; 4] {
    CANONICAL_REPUTATION_SIGNAL_ORDER.map(reputation_surface)
}

#[cfg(test)]
pub(crate) fn reputation_signal_from_weight_bps(weight_bps: u16) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER
        .iter()
        .find_map(|signal| (reputation_weight_bps(*signal) == weight_bps).then_some(*signal))
}

#[cfg(test)]
pub(crate) fn reputation_impact_from_weight_bps(weight_bps: u16) -> Option<ReputationImpact> {
    reputation_signal_from_weight_bps(weight_bps).map(reputation_impact)
}

#[cfg(test)]
pub(crate) fn reputation_signal_from_surface(
    label: &str,
    delta: i32,
    tier: u8,
    weight_bps: u16,
    score_bps: i32,
    rank_ordinal: u8,
) -> Option<ReputationSignal> {
    CANONICAL_REPUTATION_SIGNAL_ORDER.iter().find_map(|signal| {
        let surface = reputation_surface(*signal);
        (surface.label == label
            && surface.delta == delta
            && surface.tier == tier
            && surface.weight_bps == weight_bps
            && surface.score_bps == score_bps
            && surface.rank_ordinal == rank_ordinal)
            .then_some(*signal)
    })
}

#[cfg(test)]
pub(crate) fn reputation_impact_from_surface(
    label: &str,
    delta: i32,
    tier: u8,
    weight_bps: u16,
    score_bps: i32,
    rank_ordinal: u8,
) -> Option<ReputationImpact> {
    reputation_signal_from_surface(label, delta, tier, weight_bps, score_bps, rank_ordinal)
        .map(reputation_impact)
}

pub(crate) fn apply_reputation_signal(
    rec: &mut MessageIngressRecord,
    signal: ReputationSignal,
) -> ReputationSurface {
    let surface = reputation_surface(signal);
    rec.reputation_delta = Some(surface.delta);
    surface
}

pub(crate) fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}

#[cfg(test)]
mod tests;

fn main() -> Result<()> {
    let args = Args::parse();
    dispatch_command(args.cmd)
}
