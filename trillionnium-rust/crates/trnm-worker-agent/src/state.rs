use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_types::RequestStatus;

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

pub(crate) fn load_ack_records(ack_log: &PathBuf) -> Vec<AckRecord> {
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
