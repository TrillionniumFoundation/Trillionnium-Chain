use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::{Command as ProcCommand, Output, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
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

const RC_OK: i32 = 0;
const RC_DUPLICATE: i32 = 9;
const RC_NONCE_REJECTED: i32 = 10;
const RC_SKIPPED: i32 = -1;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-worker-agent",
    version,
    about = "Trillionnium PoUW worker-agent (MVP skeleton)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    PullTask {
        #[arg(long, default_value = "worker-state.json")]
        state: PathBuf,
    },
    Execute {
        #[arg(long)]
        task_id: u64,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "demo-result")]
        payload: String,
    },
    CommitReveal {
        #[arg(long)]
        task_id: u64,
        #[arg(long)]
        worker: String,
        #[arg(long)]
        result_hash: String,
        #[arg(long)]
        salt_hex: String,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
    },
    RunOnce {
        #[arg(long, default_value = "worker-state.json")]
        state: PathBuf,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "demo-result")]
        payload: String,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
    },
    RunAssigned {
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "run/message-gateway/requests.jsonl")]
        ingress_file: PathBuf,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long, default_value_t = true)]
        submit: bool,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
        #[arg(long, default_value = "./scripts/llm_adapter_mock.sh")]
        llm_adapter_cmd: String,
        #[arg(long, default_value_t = 4000)]
        verifier_max_output_chars: usize,
        #[arg(long)]
        llm_adapter_max_retries: Option<u32>,
        #[arg(long)]
        llm_adapter_backoff_ms: Option<u64>,
        #[arg(long)]
        llm_adapter_timeout_ms: Option<u64>,
    },
    FlushSubmissions {
        #[arg(long, default_value = "/tmp/trnm-worker-agent-submissions.jsonl")]
        submit_log: PathBuf,
        #[arg(long, default_value = "run/message-gateway/requests.jsonl")]
        ingress_file: PathBuf,
        #[arg(long, default_value_t = true)]
        update_ingress: bool,
        #[arg(long, default_value_t = false)]
        execute: bool,
        #[arg(long, default_value = "./scripts/worker_tx_adapter.sh")]
        adapter_cmd: String,
        #[arg(long)]
        max_retries: Option<u32>,
        #[arg(long)]
        backoff_ms: Option<u64>,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-acks.jsonl")]
        ack_log: PathBuf,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-events.jsonl")]
        event_log: PathBuf,
        #[arg(long, default_value = "/tmp/trnm-worker-agent-progress.jsonl")]
        progress_log: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerState {
    last_task_id: u64,
}

#[derive(Debug, Serialize)]
struct RunOnceOutput {
    task_id: u64,
    worker: String,
    result_hash: String,
    salt_hex: String,
    commit_hash: String,
    template_commit: String,
    template_reveal: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmissionRecord {
    ts_unix_ms: u128,
    task_id: u64,
    worker: String,
    nonce: Option<u64>,
    commit_hash: String,
    result_hash: String,
    salt_hex: String,
    commit_cmd: String,
    reveal_cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageIngressRecord {
    request_id: String,
    task_id: u64,
    channel: String,
    user_id: String,
    session_id: String,
    text: String,
    idempotency_key: String,
    status: String,
    created_at_unix_ms: u128,
    #[serde(default)]
    assigned_worker: Option<String>,
    #[serde(default)]
    assigned_at_unix_ms: Option<u128>,
    #[serde(default)]
    model_output: Option<String>,
    #[serde(default)]
    provider_request_id: Option<String>,
    #[serde(default)]
    provenance_schema_version: Option<String>,
    #[serde(default)]
    llm_provenance: Option<LlmProvenanceRecord>,
    #[serde(default)]
    result_hash: Option<String>,
    #[serde(default)]
    verifier_status: Option<String>,
    #[serde(default)]
    resolution_code: Option<String>,
    #[serde(default)]
    commit_tx_hash: Option<String>,
    #[serde(default)]
    reveal_tx_hash: Option<String>,
    #[serde(default)]
    adapter_error: Option<String>,
    #[serde(default)]
    reputation_delta: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmProvenanceRecord {
    provider: Option<String>,
    model: Option<String>,
    adapter: Option<String>,
    #[serde(default)]
    agent_protocol: Option<String>,
    #[serde(default)]
    compliance_profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckRecord {
    ts_unix_ms: u128,
    task_id: u64,
    status: String,
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct WorkerEvent {
    ts_unix_ms: u128,
    run_id: String,
    event_type: String,
    task_id: u64,
    status: String,
    reason_code: String,
    commit_rc: i32,
    reveal_rc: i32,
}

#[derive(Debug, Serialize)]
struct ProgressRecord {
    ts_unix_ms: u128,
    run_id: String,
    task_id: u64,
    state: String,
    note: String,
}

#[derive(Debug)]
struct AdapterExecResult {
    ok: bool,
    rc: i32,
    tx_hash: Option<String>,
    terminal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetryPolicy {
    max_retries: u32,
    backoff_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LlmAdapterPolicy {
    retry: RetryPolicy,
    timeout_ms: u64,
}

fn commitment(task_id: u64, result_hash_hex: &str, salt_hex: &str, worker: &str) -> String {
    let payload = format!("{}|{}|{}|{}", task_id, result_hash_hex, salt_hex, worker);
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

fn next_task_id(state: &PathBuf) -> Result<u64> {
    let mut s = if state.exists() {
        serde_json::from_str::<WorkerState>(&fs::read_to_string(state)?)?
    } else {
        WorkerState { last_task_id: 1000 }
    };
    s.last_task_id += 1;
    fs::write(state, serde_json::to_string_pretty(&s)?)?;
    Ok(s.last_task_id)
}

fn execute_payload(payload: &str, task_id: u64) -> (String, String) {
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    let result_hash = hex::encode(h.finalize());
    let salt_hex = format!("{:064x}", task_id);
    (result_hash, salt_hex)
}

fn now_ms() -> u128 {
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

fn append_submission(
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

fn load_acked(ack_log: &PathBuf) -> HashSet<u64> {
    let mut set = HashSet::new();
    if !ack_log.exists() {
        return set;
    }
    if let Ok(raw) = fs::read_to_string(ack_log) {
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(rec) = serde_json::from_str::<AckRecord>(line) {
                if rec.status == "accepted" {
                    set.insert(rec.task_id);
                }
            }
        }
    }
    set
}

struct TaskExecutionLock {
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

fn try_acquire_task_lock(ack_log: &PathBuf, task_id: u64) -> Result<Option<TaskExecutionLock>> {
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

fn is_task_acked(ack_log: &PathBuf, task_id: u64) -> bool {
    load_acked(ack_log).contains(&task_id)
}

fn load_ingress_records(path: &PathBuf) -> Result<Vec<MessageIngressRecord>> {
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

fn save_ingress_records(path: &PathBuf, records: &[MessageIngressRecord]) -> Result<()> {
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

fn transition_request_status(current: &str, to: RequestStatus) -> Result<String> {
    let from = RequestStatus::parse(current).map_err(|e| anyhow::anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}

fn append_ack(
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

fn append_event(event_log: &PathBuf, event: &WorkerEvent) -> Result<()> {
    let line = serde_json::to_string(event)?;
    append_json_line(event_log, &line)
}

fn append_progress(progress_log: &PathBuf, rec: &ProgressRecord) -> Result<()> {
    let line = serde_json::to_string(rec)?;
    append_json_line(progress_log, &line)
}

fn parse_tx_hash(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|w| {
        let raw = w.strip_prefix("tx_hash=")?;
        let cleaned = raw
            .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | '.' | ':' | ')' | ']' | '}'))
            .trim();

        if cleaned.starts_with("0x")
            && cleaned.len() == 66
            && cleaned[2..].chars().all(|c| c.is_ascii_hexdigit())
        {
            Some(cleaned.to_ascii_lowercase())
        } else {
            None
        }
    })
}

fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED)
}

fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(attempt as u64 + 1)
}

fn run_adapter_with_retry(
    cmd: &str,
    max_retries: u32,
    backoff_ms: u64,
) -> Result<AdapterExecResult> {
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = ProcCommand::new("sh").arg("-lc").arg(cmd).output()?;
        let rc = out.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tx_hash = parse_tx_hash(&stdout).or_else(|| parse_tx_hash(&stderr));

        if out.status.success() {
            return Ok(AdapterExecResult {
                ok: true,
                rc: RC_OK,
                tx_hash,
                terminal: true,
            });
        }

        last_rc = rc;
        if tx_hash.is_some() {
            last_tx_hash = tx_hash;
        }

        // deterministic rejections (duplicate/nonce_rejected) should not retry.
        if is_deterministic_rejection(rc) {
            return Ok(AdapterExecResult {
                ok: false,
                rc,
                tx_hash: last_tx_hash,
                terminal: true,
            });
        }

        if attempt < max_retries {
            thread::sleep(Duration::from_millis(backoff_delay_ms(backoff_ms, attempt)));
        }
    }

    Ok(AdapterExecResult {
        ok: false,
        rc: last_rc,
        tx_hash: last_tx_hash,
        terminal: false,
    })
}

#[derive(Debug, Deserialize)]
struct LlmAdapterResponse {
    output_text: String,
    #[serde(default)]
    provider_request_id: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    adapter: Option<String>,
    #[serde(default)]
    agent_protocol: Option<String>,
    #[serde(default)]
    compliance_profile: Option<String>,
}

fn truncate_for_error(raw: &str, max_chars: usize) -> String {
    let total = raw.chars().count();
    if total <= max_chars {
        return raw.to_string();
    }
    let prefix: String = raw.chars().take(max_chars).collect();
    format!("{}…(truncated, {} chars total)", prefix, total)
}

fn parse_u32_with_min(raw: Option<&str>, default: u32, min: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default)
}

fn parse_u64_with_min(raw: Option<&str>, default: u64, min: u64) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
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

fn resolve_tx_retry_policy(
    max_retries_cli: Option<u32>,
    backoff_ms_cli: Option<u64>,
) -> RetryPolicy {
    RetryPolicy {
        max_retries: resolve_u32(
            max_retries_cli,
            env::var(TX_ADAPTER_MAX_RETRIES_ENV).ok().as_deref(),
            DEFAULT_TX_ADAPTER_MAX_RETRIES,
            0,
        ),
        backoff_ms: resolve_u64(
            backoff_ms_cli,
            env::var(TX_ADAPTER_BACKOFF_MS_ENV).ok().as_deref(),
            DEFAULT_TX_ADAPTER_BACKOFF_MS,
            0,
        ),
    }
}

fn resolve_llm_adapter_policy(
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

fn run_shell_with_timeout(cmd: &str, timeout: Duration) -> Result<Output> {
    let mut child = ProcCommand::new("sh")
        .arg("-lc")
        .arg(cmd)
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
enum AdapterErrorKind {
    Retriable,
    NonRetriable,
}

#[derive(Debug, Clone)]
struct AdapterError {
    kind: AdapterErrorKind,
    context: String,
}

fn exp_backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(1u64.checked_shl(attempt.min(62)).unwrap_or(u64::MAX))
}

fn run_llm_adapter_once(
    adapter_cmd: &str,
    prompt: &str,
    timeout: Duration,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    let cmd = format!("{} {}", adapter_cmd, shell_escape::escape(prompt.into()));
    let out = run_shell_with_timeout(&cmd, timeout).map_err(|e| AdapterError {
        kind: AdapterErrorKind::Retriable,
        context: e.to_string(),
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
    let parse_whole = serde_json::from_str::<LlmAdapterResponse>(&stdout);
    let resp = if let Ok(resp) = parse_whole {
        resp
    } else {
        let fallback_line = stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| line.starts_with('{') && line.ends_with('}'));

        match fallback_line {
            Some(line) => serde_json::from_str::<LlmAdapterResponse>(line).map_err(|e| {
                AdapterError {
                    kind: AdapterErrorKind::NonRetriable,
                    context: format!(
                        "llm adapter invalid json: {} raw={}",
                        e,
                        truncate_for_error(&stdout, 512)
                    ),
                }
            })?,
            None => {
                return Err(AdapterError {
                    kind: AdapterErrorKind::NonRetriable,
                    context: format!(
                        "llm adapter invalid json: no-json-line raw={}",
                        truncate_for_error(&stdout, 512)
                    ),
                });
            }
        }
    };

    Ok(resp)
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
                    sleeper(Duration::from_millis(exp_backoff_delay_ms(
                        backoff_ms, attempt,
                    )));
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

fn run_llm_adapter_with_retry(
    adapter_cmd: &str,
    prompt: &str,
    retry: RetryPolicy,
    timeout: Duration,
) -> std::result::Result<LlmAdapterResponse, AdapterError> {
    run_llm_adapter_with_retry_inner(
        retry.max_retries,
        retry.backoff_ms,
        || run_llm_adapter_once(adapter_cmd, prompt, timeout),
        thread::sleep,
    )
}

fn is_invisible_filler(c: char) -> bool {
    matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
}

fn verify_model_output(output: &str, max_chars: usize) -> (&'static str, &'static str) {
    let trimmed = output.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .any(|c| !c.is_whitespace() && !is_invisible_filler(c))
    {
        return ("rejected", "empty_output");
    }
    if trimmed.chars().count() > max_chars {
        return ("rejected", "output_too_long");
    }
    ("accepted", "ok")
}

fn normalized_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    match normalized.as_str() {
        "mcp" | "a2a" => Some(normalized),
        _ => None,
    }
}

fn normalized_compliance_profile(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    let starts_and_ends_alnum = normalized
        .chars()
        .next()
        .zip(normalized.chars().last())
        .map(|(start, end)| start.is_ascii_alphanumeric() && end.is_ascii_alphanumeric())
        .unwrap_or(false);
    if is_allowed && starts_and_ends_alnum && normalized.len() <= 64 {
        Some(normalized)
    } else {
        None
    }
}

fn attach_llm_provenance(rec: &mut MessageIngressRecord, llm: &LlmAdapterResponse) {
    rec.provider_request_id = normalized_optional_field(llm.provider_request_id.as_deref());

    let provider = normalized_optional_field(llm.provider.as_deref());
    let model = normalized_optional_field(llm.model.as_deref());
    let adapter = normalized_optional_field(llm.adapter.as_deref());
    let agent_protocol = normalized_agent_protocol(llm.agent_protocol.as_deref());
    let compliance_profile =
        normalized_compliance_profile(llm.compliance_profile.as_deref());

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

fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
    match err.kind {
        AdapterErrorKind::Retriable => ("adapter_error", "retry_exhausted"),
        AdapterErrorKind::NonRetriable => ("adapter_error", "non_retriable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReputationSignal {
    Accepted,
    VerifierRejected,
    AdapterRetryExhausted,
    AdapterNonRetriable,
}

fn reputation_delta(signal: ReputationSignal) -> i32 {
    match signal {
        ReputationSignal::Accepted => 3,
        ReputationSignal::VerifierRejected => -2,
        ReputationSignal::AdapterRetryExhausted => -1,
        ReputationSignal::AdapterNonRetriable => -3,
    }
}

fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_request_status_accepts_benign_formatting_variants() {
        let next = transition_request_status("  open ", RequestStatus::Assigned)
            .expect("OPEN -> ASSIGNED should parse with whitespace/case drift");
        assert_eq!(next, RequestStatus::Assigned.as_str());

        let next = transition_request_status("aSsIgNeD", RequestStatus::CommitQueued)
            .expect("ASSIGNED -> COMMIT_QUEUED should parse case-insensitively");
        assert_eq!(next, RequestStatus::CommitQueued.as_str());
    }

    #[test]
    fn transition_request_status_rejects_malformed_state_with_stable_diagnostic() {
        let err = transition_request_status(" pending-ish ", RequestStatus::Assigned)
            .expect_err("unknown states must be rejected");
        assert!(
            err.to_string().contains("unknown request state"),
            "unexpected error text: {}",
            err
        );
    }

    #[test]
    fn deterministic_rejection_codes_are_stable() {
        assert!(is_deterministic_rejection(RC_DUPLICATE));
        assert!(is_deterministic_rejection(RC_NONCE_REJECTED));
        assert!(!is_deterministic_rejection(RC_OK));
        assert!(!is_deterministic_rejection(42));
    }

    #[test]
    fn idempotent_only_accepts_duplicate() {
        assert!(is_idempotent_duplicate_ok(RC_DUPLICATE));
        assert!(!is_idempotent_duplicate_ok(RC_NONCE_REJECTED));
        assert!(!is_idempotent_duplicate_ok(RC_OK));
    }

    #[test]
    fn terminal_commit_reject_skips_reveal_execution_gate() {
        let commit_res = AdapterExecResult {
            ok: false,
            rc: RC_NONCE_REJECTED,
            tx_hash: None,
            terminal: true,
        };

        assert!(!should_execute_reveal(&commit_res));
    }

    #[test]
    fn duplicate_commit_still_executes_reveal_gate() {
        let commit_res = AdapterExecResult {
            ok: false,
            rc: RC_DUPLICATE,
            tx_hash: None,
            terminal: true,
        };

        assert!(should_execute_reveal(&commit_res));
    }

    #[test]
    fn backoff_delay_is_linear_and_saturating() {
        assert_eq!(backoff_delay_ms(200, 0), 200);
        assert_eq!(backoff_delay_ms(200, 1), 400);
        assert_eq!(backoff_delay_ms(200, 2), 600);

        // saturation guard (no overflow panic/wrap)
        assert_eq!(backoff_delay_ms(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn parse_tx_hash_accepts_quoted_and_trailing_punctuated_tokens() {
        let mixed_case = "tx_hash=\"0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd\",";
        let parsed = parse_tx_hash(mixed_case).expect("hash should parse");
        assert_eq!(
            parsed,
            "0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        );

        let sentence_tail = "submitted tx_hash=0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd. next";
        let parsed_tail = parse_tx_hash(sentence_tail).expect("hash with sentence punctuation should parse");
        assert_eq!(
            parsed_tail,
            "0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        );
    }

    #[test]
    fn parse_tx_hash_rejects_malformed_or_partial_values() {
        assert!(parse_tx_hash("tx_hash=0xdeadbeef").is_none());
        assert!(parse_tx_hash("tx_hash=not-a-hash").is_none());
        assert!(parse_tx_hash("tx_hash=0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn llm_adapter_timeout_triggers() {
        let cmd = "sleep 0.2; echo '{\"output_text\":\"late\"}'";
        let err = run_shell_with_timeout(cmd, Duration::from_millis(30)).unwrap_err();
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn config_defaults_apply_when_cli_and_env_missing() {
        let llm = LlmAdapterPolicy {
            retry: RetryPolicy {
                max_retries: resolve_u32(None, None, DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
                backoff_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
            },
            timeout_ms: resolve_u64(None, None, DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
        };
        let tx = RetryPolicy {
            max_retries: resolve_u32(None, None, DEFAULT_TX_ADAPTER_MAX_RETRIES, 0),
            backoff_ms: resolve_u64(None, None, DEFAULT_TX_ADAPTER_BACKOFF_MS, 0),
        };

        assert_eq!(llm.retry.max_retries, DEFAULT_LLM_ADAPTER_MAX_RETRIES);
        assert_eq!(llm.retry.backoff_ms, DEFAULT_LLM_ADAPTER_BACKOFF_MS);
        assert_eq!(llm.timeout_ms, DEFAULT_LLM_ADAPTER_TIMEOUT_MS);
        assert_eq!(tx.max_retries, DEFAULT_TX_ADAPTER_MAX_RETRIES);
        assert_eq!(tx.backoff_ms, DEFAULT_TX_ADAPTER_BACKOFF_MS);
    }

    #[test]
    fn config_invalid_values_fallback_to_default() {
        assert_eq!(
            resolve_u32(None, Some("bad"), DEFAULT_LLM_ADAPTER_MAX_RETRIES, 0),
            DEFAULT_LLM_ADAPTER_MAX_RETRIES
        );
        assert_eq!(
            resolve_u64(None, Some("bad"), DEFAULT_LLM_ADAPTER_BACKOFF_MS, 0),
            DEFAULT_LLM_ADAPTER_BACKOFF_MS
        );
        assert_eq!(
            resolve_u64(None, Some("0"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
            DEFAULT_LLM_ADAPTER_TIMEOUT_MS
        );
        assert_eq!(
            resolve_u64(Some(0), Some("8000"), DEFAULT_LLM_ADAPTER_TIMEOUT_MS, 1),
            8000
        );
    }

    #[test]
    fn llm_adapter_non_timeout_path_is_ok() {
        let cmd = "echo '{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}'";
        let out = run_shell_with_timeout(cmd, Duration::from_secs(1)).unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let parsed: LlmAdapterResponse = serde_json::from_str(&stdout).unwrap();
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
    }

    #[test]
    fn llm_adapter_accepts_last_json_line_when_stdout_has_noise() {
        let cmd = "printf 'debug: adapter warmup\\n{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}\\n'";
        let parsed = run_llm_adapter_once("sh -lc", cmd, Duration::from_secs(1)).unwrap();
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
    }

    #[test]
    fn truncate_for_error_marks_truncated_payloads() {
        let raw = "x".repeat(600);
        let truncated = truncate_for_error(&raw, 32);
        assert!(truncated.starts_with("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(truncated.contains("truncated"));
        assert!(truncated.contains("600 chars total"));
    }

    #[test]
    fn adapter_error_classification_is_unified_failed_adapter() {
        let retry_exhausted = AdapterError {
            kind: AdapterErrorKind::Retriable,
            context: "llm adapter timeout after 3000ms".to_string(),
        };
        let non_retriable = AdapterError {
            kind: AdapterErrorKind::NonRetriable,
            context: "llm adapter invalid json".to_string(),
        };
        assert_eq!(
            classify_adapter_error(&retry_exhausted),
            ("adapter_error", "retry_exhausted")
        );
        assert_eq!(
            classify_adapter_error(&non_retriable),
            ("adapter_error", "non_retriable")
        );
    }

    #[test]
    fn reputation_delta_maps_market_penalty_and_reward_signals() {
        assert_eq!(reputation_delta(ReputationSignal::Accepted), 3);
        assert_eq!(reputation_delta(ReputationSignal::VerifierRejected), -2);
        assert_eq!(reputation_delta(ReputationSignal::AdapterRetryExhausted), -1);
        assert_eq!(reputation_delta(ReputationSignal::AdapterNonRetriable), -3);
    }

    #[test]
    fn verifier_rejection_penalty_sits_between_retryable_and_non_retriable_adapter_failures() {
        let verifier_penalty = reputation_delta(ReputationSignal::VerifierRejected);
        let retryable_penalty = reputation_delta(ReputationSignal::AdapterRetryExhausted);
        let non_retriable_penalty = reputation_delta(ReputationSignal::AdapterNonRetriable);

        assert!(
            verifier_penalty < retryable_penalty,
            "verifier rejection should be stricter than transient adapter exhaustion"
        );
        assert!(
            verifier_penalty > non_retriable_penalty,
            "verifier rejection should remain less severe than deterministic adapter failures"
        );
    }

    #[test]
    fn adapter_error_signal_maps_retryability_to_penalty_tier() {
        assert_eq!(
            adapter_error_signal(AdapterErrorKind::Retriable),
            ReputationSignal::AdapterRetryExhausted
        );
        assert_eq!(
            adapter_error_signal(AdapterErrorKind::NonRetriable),
            ReputationSignal::AdapterNonRetriable
        );
    }

    #[test]
    fn verify_model_output_enforces_trimmed_empty_and_char_limit_boundaries() {
        assert_eq!(verify_model_output("   \n\t", 8), ("rejected", "empty_output"));

        // Zero-width fillers should not pass verifier checks as meaningful output.
        assert_eq!(
            verify_model_output("\u{200B}\u{200C}\u{FEFF}", 8),
            ("rejected", "empty_output")
        );

        // Limit is measured in characters (not bytes) to keep verifier behavior predictable.
        let within = "你好ab"; // 4 chars
        assert_eq!(verify_model_output(within, 4), ("accepted", "ok"));

        let over = "你好abc"; // 5 chars
        assert_eq!(verify_model_output(over, 4), ("rejected", "output_too_long"));

        // Leading/trailing transport whitespace should not cause false rejections.
        assert_eq!(verify_model_output(" 你好ab \n", 4), ("accepted", "ok"));

        // Mixed visible + zero-width should still count as meaningful content.
        assert_eq!(verify_model_output("\u{200B}ok\u{200D}", 4), ("accepted", "ok"));
    }

    #[test]
    fn llm_adapter_retry_succeeds_within_budget() {
        let mut attempt = 0u32;
        let mut slept = vec![];
        let res = run_llm_adapter_with_retry_inner(
            2,
            50,
            || {
                attempt += 1;
                if attempt < 3 {
                    Err(AdapterError {
                        kind: AdapterErrorKind::Retriable,
                        context: format!("transient-{}", attempt),
                    })
                } else {
                    Ok(LlmAdapterResponse {
                        output_text: "ok".to_string(),
                        provider_request_id: None,
                        provider: None,
                        model: None,
                        adapter: None,
                        agent_protocol: None,
                        compliance_profile: None,
                    })
                }
            },
            |d| slept.push(d.as_millis() as u64),
        )
        .unwrap();

        assert_eq!(res.output_text, "ok");
        assert_eq!(attempt, 3);
        assert_eq!(slept, vec![50, 100]);
    }

    #[test]
    fn llm_adapter_retry_budget_exhausted_returns_last_error() {
        let mut attempt = 0u32;
        let mut slept = vec![];
        let err = run_llm_adapter_with_retry_inner(
            2,
            20,
            || {
                attempt += 1;
                Err(AdapterError {
                    kind: AdapterErrorKind::Retriable,
                    context: format!("timeout-{}", attempt),
                })
            },
            |d| slept.push(d.as_millis() as u64),
        )
        .unwrap_err();

        assert_eq!(attempt, 3);
        assert_eq!(slept, vec![20, 40]);
        assert_eq!(err.kind, AdapterErrorKind::Retriable);
        assert_eq!(err.context, "timeout-3");
    }

    #[test]
    fn llm_adapter_non_retriable_fails_fast() {
        let mut attempt = 0u32;
        let mut slept = vec![];
        let err = run_llm_adapter_with_retry_inner(
            5,
            20,
            || {
                attempt += 1;
                Err(AdapterError {
                    kind: AdapterErrorKind::NonRetriable,
                    context: "invalid-json".to_string(),
                })
            },
            |d| slept.push(d.as_millis() as u64),
        )
        .unwrap_err();

        assert_eq!(attempt, 1);
        assert!(slept.is_empty());
        assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
        assert_eq!(err.context, "invalid-json");
    }

    #[test]
    fn task_lock_prevents_parallel_replay_for_same_task() {
        let ack_log =
            std::env::temp_dir().join(format!("trnm-worker-agent-ack-{}.jsonl", now_ms()));
        let guard = try_acquire_task_lock(&ack_log, 42)
            .expect("acquire lock")
            .expect("first lock should succeed");
        assert!(
            try_acquire_task_lock(&ack_log, 42)
                .expect("second lock call")
                .is_none(),
            "second lock should be blocked"
        );
        drop(guard);
        assert!(
            try_acquire_task_lock(&ack_log, 42)
                .expect("third lock call")
                .is_some(),
            "lock should be released after drop"
        );
        let _ = fs::remove_file(&ack_log);
    }

    #[test]
    fn is_task_acked_only_true_for_accepted_records() {
        let ack_log =
            std::env::temp_dir().join(format!("trnm-worker-agent-ack-{}.jsonl", now_ms()));
        fs::write(
            &ack_log,
            "{\"ts_unix_ms\":1,\"task_id\":1,\"status\":\"rejected\"}\n{\"ts_unix_ms\":2,\"task_id\":2,\"status\":\"accepted\"}\n",
        )
        .expect("write ack log");

        assert!(!is_task_acked(&ack_log, 1));
        assert!(is_task_acked(&ack_log, 2));
        let _ = fs::remove_file(&ack_log);
    }

    #[test]
    fn message_ingress_backward_compat_defaults_provider_request_id() {
        let raw = r#"{"request_id":"r1","task_id":7,"channel":"telegram","user_id":"u1","session_id":"s1","text":"hello","idempotency_key":"ik1","status":"assigned","created_at_unix_ms":1}"#;
        let rec: MessageIngressRecord = serde_json::from_str(raw).expect("parse ingress record");
        assert_eq!(rec.provider_request_id, None);
        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_persists_provider_request_id() {
        let mut rec = MessageIngressRecord {
            request_id: "r1".to_string(),
            task_id: 9,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik1".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("provider-123".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: None,
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-123"));
        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.provider.as_deref(), Some("openai"));
        assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(prov.adapter.as_deref(), Some("mcp"));
        assert_eq!(prov.agent_protocol, None);
        assert_eq!(prov.compliance_profile, None);
    }

    #[test]
    fn attach_llm_provenance_keeps_schema_empty_without_structured_fields() {
        let mut rec = MessageIngressRecord {
            request_id: "r2".to_string(),
            task_id: 10,
            channel: "telegram".to_string(),
            user_id: "u2".to_string(),
            session_id: "s2".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik2".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("provider-opaque-id".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-opaque-id"));
        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_uses_v2_when_protocol_or_compliance_present() {
        let mut rec = MessageIngressRecord {
            request_id: "r3".to_string(),
            task_id: 11,
            channel: "telegram".to_string(),
            user_id: "u3".to_string(),
            session_id: "s3".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik3".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("provider-321".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-321"));
        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(prov.compliance_profile.as_deref(), Some("cn-pii-restricted"));
    }

    #[test]
    fn attach_llm_provenance_trims_whitespace_and_drops_empty_fields() {
        let mut rec = MessageIngressRecord {
            request_id: "r4".to_string(),
            task_id: 12,
            channel: "telegram".to_string(),
            user_id: "u4".to_string(),
            session_id: "s4".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik4".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("  provider-444  ".to_string()),
            provider: Some("  ".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("   ".to_string()),
            compliance_profile: Some("  cn-pii-restricted  ".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-444"));
        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.provider, None);
        assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(prov.adapter.as_deref(), Some("mcp"));
        assert_eq!(prov.agent_protocol, None);
        assert_eq!(prov.compliance_profile.as_deref(), Some("cn-pii-restricted"));
    }

    #[test]
    fn attach_llm_provenance_normalizes_agent_protocol_casing() {
        let mut rec = MessageIngressRecord {
            request_id: "r5".to_string(),
            task_id: 13,
            channel: "telegram".to_string(),
            user_id: "u5".to_string(),
            session_id: "s5".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik5".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("  MCP  ".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));
    }

    #[test]
    fn attach_llm_provenance_drops_unsupported_agent_protocol() {
        let mut rec = MessageIngressRecord {
            request_id: "r5b".to_string(),
            task_id: 131,
            channel: "telegram".to_string(),
            user_id: "u5".to_string(),
            session_id: "s5".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik5b".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("prid-1".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some(" custom-proto ".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_normalizes_compliance_profile_casing() {
        let mut rec = MessageIngressRecord {
            request_id: "r6".to_string(),
            task_id: 14,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: Some("  CN-PII-Restricted  ".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(
            prov.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn attach_llm_provenance_rejects_invalid_compliance_profile_chars() {
        let mut rec = MessageIngressRecord {
            request_id: "r6b".to_string(),
            task_id: 141,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6b".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("provider-6b".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: Some("CN/PII/Restricted".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_rejects_boundary_separators_in_compliance_profile() {
        let mut rec = MessageIngressRecord {
            request_id: "r6c".to_string(),
            task_id: 142,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6c".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: None,
            provenance_schema_version: None,
            llm_provenance: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };
        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: Some("provider-6c".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: Some("-cn-pii-restricted_".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn normalized_compliance_profile_accepts_64_char_boundary() {
        let profile = "a".repeat(64);
        assert_eq!(
            normalized_compliance_profile(Some(&profile)).as_deref(),
            Some(profile.as_str())
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_over_64_chars() {
        let profile = "a".repeat(65);
        assert_eq!(normalized_compliance_profile(Some(&profile)), None);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::PullTask { state } => {
            let task_id = next_task_id(&state)?;
            println!("[agent] pulled task_id={}", task_id);
        }
        Command::Execute {
            task_id,
            worker,
            payload,
        } => {
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            println!("[agent] executed task_id={} worker={}", task_id, worker);
            println!("result_hash={}", result_hash);
            println!("salt_hex={}", salt_hex);
        }
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
            submit,
            submit_log,
        } => {
            let c = commitment(task_id, &result_hash, &salt_hex, &worker);
            println!("[agent] task_id={} worker={}", task_id, worker);
            println!("commit_hash={}", c);
            println!(
                "template_commit=trnm-node tx commit-result {} {} {} {}",
                task_id, worker, c, task_id
            );
            println!(
                "template_reveal=trnm-node tx reveal-result {} {} {}",
                task_id, result_hash, salt_hex
            );
            if submit {
                append_submission(&submit_log, task_id, &worker, &c, &result_hash, &salt_hex)?;
                println!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunOnce {
            state,
            worker,
            payload,
            submit,
            submit_log,
        } => {
            let task_id = next_task_id(&state)?;
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            let commit_hash = commitment(task_id, &result_hash, &salt_hex, &worker);
            if submit {
                append_submission(
                    &submit_log,
                    task_id,
                    &worker,
                    &commit_hash,
                    &result_hash,
                    &salt_hex,
                )?;
            }
            let out = RunOnceOutput {
                task_id,
                worker: worker.clone(),
                result_hash: result_hash.clone(),
                salt_hex: salt_hex.clone(),
                commit_hash: commit_hash.clone(),
                template_commit: format!(
                    "trnm-node tx commit-result {} {} {} {}",
                    task_id, worker, commit_hash, task_id
                ),
                template_reveal: format!(
                    "trnm-node tx reveal-result {} {} {}",
                    task_id, result_hash, salt_hex
                ),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
            if submit {
                eprintln!("submitted=true submit_log={}", submit_log.display());
            }
        }
        Command::RunAssigned {
            worker,
            ingress_file,
            limit,
            submit,
            submit_log,
            llm_adapter_cmd,
            verifier_max_output_chars,
            llm_adapter_max_retries,
            llm_adapter_backoff_ms,
            llm_adapter_timeout_ms,
        } => {
            let llm_policy = resolve_llm_adapter_policy(
                llm_adapter_max_retries,
                llm_adapter_backoff_ms,
                llm_adapter_timeout_ms,
            );
            let mut records = load_ingress_records(&ingress_file)?;
            let mut n = 0usize;
            for rec in records.iter_mut() {
                if n >= limit {
                    break;
                }
                if rec.status != RequestStatus::Assigned.as_str() {
                    continue;
                }
                if rec.assigned_worker.as_deref() != Some(worker.as_str()) {
                    continue;
                }

                let llm = match run_llm_adapter_with_retry(
                    &llm_adapter_cmd,
                    &rec.text,
                    llm_policy.retry,
                    Duration::from_millis(llm_policy.timeout_ms),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let (resolution_code, failure_tag) = classify_adapter_error(&e);
                        rec.status =
                            transition_request_status(&rec.status, RequestStatus::FailedAdapter)?;
                        rec.verifier_status = Some("rejected".to_string());
                        rec.resolution_code = Some(resolution_code.to_string());
                        rec.adapter_error = Some(e.context.clone());
                        rec.reputation_delta = Some(reputation_delta(adapter_error_signal(e.kind)));
                        n += 1;
                        println!(
                            "[assigned] request_id={} task_id={} worker={} status=FAILED_ADAPTER({}) retryable={} error={}",
                            rec.request_id,
                            rec.task_id,
                            worker,
                            failure_tag,
                            matches!(e.kind, AdapterErrorKind::Retriable),
                            e.context
                        );
                        continue;
                    }
                };
                let (v_status, resolution_code) =
                    verify_model_output(&llm.output_text, verifier_max_output_chars);
                attach_llm_provenance(rec, &llm);
                rec.model_output = Some(llm.output_text.clone());
                rec.verifier_status = Some(v_status.to_string());
                rec.resolution_code = Some(resolution_code.to_string());

                if v_status != "accepted" {
                    rec.status = transition_request_status(&rec.status, RequestStatus::Rejected)?;
                    rec.reputation_delta = Some(reputation_delta(ReputationSignal::VerifierRejected));
                    n += 1;
                    println!(
                        "[assigned] request_id={} task_id={} worker={} verifier_status={} resolution_code={}",
                        rec.request_id, rec.task_id, worker, v_status, resolution_code
                    );
                    continue;
                }

                let payload = llm.output_text;
                let (result_hash, salt_hex) = execute_payload(&payload, rec.task_id);
                let commit_hash = commitment(rec.task_id, &result_hash, &salt_hex, &worker);
                rec.result_hash = Some(result_hash.clone());
                if submit {
                    append_submission(
                        &submit_log,
                        rec.task_id,
                        &worker,
                        &commit_hash,
                        &result_hash,
                        &salt_hex,
                    )?;
                }
                rec.status = transition_request_status(&rec.status, RequestStatus::CommitQueued)?;
                rec.reputation_delta = Some(reputation_delta(ReputationSignal::Accepted));
                n += 1;
                println!(
                    "[assigned] request_id={} task_id={} worker={} result_hash={} submit={} provider_request_id={}",
                    rec.request_id,
                    rec.task_id,
                    worker,
                    result_hash,
                    submit,
                    rec.provider_request_id.as_deref().unwrap_or("-")
                );
            }
            save_ingress_records(&ingress_file, &records)?;
            println!(
                "[agent] run-assigned processed={} ingress={} submit_log={} adapter={} adapter_retries={} adapter_backoff_ms={} adapter_timeout_ms={}",
                n,
                ingress_file.display(),
                submit_log.display(),
                llm_adapter_cmd,
                llm_policy.retry.max_retries,
                llm_policy.retry.backoff_ms,
                llm_policy.timeout_ms
            );
        }
        Command::FlushSubmissions {
            submit_log,
            ingress_file,
            update_ingress,
            execute,
            adapter_cmd,
            max_retries,
            backoff_ms,
            ack_log,
            event_log,
            progress_log,
        } => {
            let tx_retry = resolve_tx_retry_policy(max_retries, backoff_ms);
            if !submit_log.exists() {
                println!("[agent] no submit log found: {}", submit_log.display());
                return Ok(());
            }
            let raw = fs::read_to_string(&submit_log)?;
            let mut n = 0usize;
            let mut skipped = 0usize;
            let mut acked = load_acked(&ack_log);
            let run_id = format!("flush-{}-{}", now_ms(), std::process::id());
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let rec: SubmissionRecord = serde_json::from_str(line)?;
                n += 1;

                if acked.contains(&rec.task_id) {
                    skipped += 1;
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "done".to_string(),
                            note: "already_acked_skip".to_string(),
                        },
                    )?;
                    println!("[skip] task_id={} already_acked=true", rec.task_id);
                    continue;
                }

                if !execute {
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "pending".to_string(),
                            note: "dry_run_only".to_string(),
                        },
                    )?;
                    println!(
                        "[dry-run] adapter={} commit {} {} {}",
                        adapter_cmd, rec.task_id, rec.worker, rec.commit_hash
                    );
                    println!(
                        "[dry-run] adapter={} reveal {} {} {}",
                        adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex
                    );
                } else {
                    let Some(_task_lock) = try_acquire_task_lock(&ack_log, rec.task_id)? else {
                        skipped += 1;
                        append_progress(
                            &progress_log,
                            &ProgressRecord {
                                ts_unix_ms: now_ms(),
                                run_id: run_id.clone(),
                                task_id: rec.task_id,
                                state: "pending".to_string(),
                                note: "concurrent_replay_skip".to_string(),
                            },
                        )?;
                        println!("[skip] task_id={} concurrent_replay=true", rec.task_id);
                        continue;
                    };

                    if is_task_acked(&ack_log, rec.task_id) {
                        skipped += 1;
                        acked.insert(rec.task_id);
                        append_progress(
                            &progress_log,
                            &ProgressRecord {
                                ts_unix_ms: now_ms(),
                                run_id: run_id.clone(),
                                task_id: rec.task_id,
                                state: "done".to_string(),
                                note: "already_acked_after_lock".to_string(),
                            },
                        )?;
                        println!(
                            "[skip] task_id={} already_acked_after_lock=true",
                            rec.task_id
                        );
                        continue;
                    }

                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: "processing".to_string(),
                            note: format!(
                                "adapter={} retries={} backoff_ms={}",
                                adapter_cmd, tx_retry.max_retries, tx_retry.backoff_ms
                            ),
                        },
                    )?;
                    let nonce = rec.nonce.unwrap_or(rec.task_id);
                    let cmd1 = format!(
                        "{} commit {} {} {} {}",
                        adapter_cmd, rec.task_id, rec.worker, rec.commit_hash, nonce
                    );
                    let cmd2 = format!(
                        "{} reveal {} {} {}",
                        adapter_cmd, rec.task_id, rec.result_hash, rec.salt_hex
                    );

                    let commit_res =
                        run_adapter_with_retry(&cmd1, tx_retry.max_retries, tx_retry.backoff_ms)?;
                    let reveal_executed = should_execute_reveal(&commit_res);
                    let reveal_res = if reveal_executed {
                        run_adapter_with_retry(&cmd2, tx_retry.max_retries, tx_retry.backoff_ms)?
                    } else {
                        AdapterExecResult {
                            ok: false,
                            rc: RC_SKIPPED,
                            tx_hash: None,
                            terminal: true,
                        }
                    };

                    println!(
                        "[submitted] task_id={} commit_ok={} reveal_ok={} reveal_executed={} commit_rc={} reveal_rc={} commit_tx_hash={} reveal_tx_hash={} adapter={} retries={} backoff_ms={}",
                        rec.task_id,
                        commit_res.ok,
                        reveal_res.ok,
                        reveal_executed,
                        commit_res.rc,
                        reveal_res.rc,
                        commit_res.tx_hash.as_deref().unwrap_or("-"),
                        reveal_res.tx_hash.as_deref().unwrap_or("-"),
                        adapter_cmd,
                        tx_retry.max_retries,
                        tx_retry.backoff_ms
                    );

                    let commit_idempotent_ok = should_execute_reveal(&commit_res);
                    let reveal_idempotent_ok =
                        reveal_res.ok || is_idempotent_duplicate_ok(reveal_res.rc);

                    let (ack_status, reason_code, ack_reason) = if commit_idempotent_ok
                        && reveal_idempotent_ok
                    {
                        (
                            "accepted",
                            "idempotent_ok",
                            format!(
                                "idempotent-ok commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else if !commit_idempotent_ok && commit_res.terminal {
                        (
                                "rejected",
                                "commit_rejected_skip_reveal",
                                format!(
                                    "deterministic-commit-rejection-skip-reveal commit_rc={} reveal_rc={}",
                                    commit_res.rc, reveal_res.rc
                                ),
                            )
                    } else if commit_res.terminal || reveal_res.terminal {
                        (
                            "rejected",
                            "deterministic_rejection",
                            format!(
                                "deterministic-rejection commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else {
                        (
                            "failed",
                            "retry_exhausted_or_transient",
                            format!(
                                "transient-or-exhausted-retries commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    };

                    append_ack(
                        &ack_log,
                        rec.task_id,
                        ack_status,
                        commit_res.tx_hash.clone(),
                        reveal_res.tx_hash.clone(),
                        Some(reason_code.to_string()),
                        Some(run_id.clone()),
                    )?;

                    if update_ingress {
                        let mut ingress = load_ingress_records(&ingress_file)?;
                        let mut changed = false;
                        for ir in ingress.iter_mut() {
                            if ir.task_id == rec.task_id {
                                ir.commit_tx_hash = commit_res.tx_hash.clone();
                                ir.reveal_tx_hash = reveal_res.tx_hash.clone();
                                ir.resolution_code = Some(reason_code.to_string());
                                ir.verifier_status = Some(if ack_status == "accepted" {
                                    "accepted".to_string()
                                } else {
                                    "rejected".to_string()
                                });
                                ir.status = match ack_status {
                                    "accepted" => transition_request_status(
                                        &ir.status,
                                        RequestStatus::RevealSubmitted,
                                    )?,
                                    "rejected" => transition_request_status(
                                        &ir.status,
                                        RequestStatus::Rejected,
                                    )?,
                                    _ => transition_request_status(
                                        &ir.status,
                                        RequestStatus::FailedSubmission,
                                    )?,
                                };
                                changed = true;
                            }
                        }
                        if changed {
                            save_ingress_records(&ingress_file, &ingress)?;
                        }
                    }

                    append_event(
                        &event_log,
                        &WorkerEvent {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            event_type: "ack_written".to_string(),
                            task_id: rec.task_id,
                            status: ack_status.to_string(),
                            reason_code: reason_code.to_string(),
                            commit_rc: commit_res.rc,
                            reveal_rc: reveal_res.rc,
                        },
                    )?;

                    let progress_state = match ack_status {
                        "accepted" => "done",
                        "rejected" => "rejected",
                        _ => "failed",
                    };
                    append_progress(
                        &progress_log,
                        &ProgressRecord {
                            ts_unix_ms: now_ms(),
                            run_id: run_id.clone(),
                            task_id: rec.task_id,
                            state: progress_state.to_string(),
                            note: reason_code.to_string(),
                        },
                    )?;

                    if ack_status == "accepted" {
                        acked.insert(rec.task_id);
                    }

                    println!(
                        "[ack] run_id={} task_id={} status={} reason={} reason_code={}",
                        run_id, rec.task_id, ack_status, ack_reason, reason_code
                    );
                }
            }
            println!("[agent] flushed_records={} skipped={} execute={} ack_log={} event_log={} progress_log={} run_id={}", n, skipped, execute, ack_log.display(), event_log.display(), progress_log.display(), run_id);
        }
    }
    Ok(())
}
