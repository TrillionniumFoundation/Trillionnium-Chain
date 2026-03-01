use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command as ProcCommand, Output, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod proof_adapter;

use proof_adapter::{ProofAdapter, StandardProofAdapter};
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
const RC_SLO_VIOLATION: i32 = 11;
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
    ExportAudit {
        #[arg(long, default_value = "run/message-gateway/requests.jsonl")]
        ingress_file: PathBuf,
        #[arg(long, default_value = "audit-export.jsonl")]
        output_file: PathBuf,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EnterpriseAuditExportRecord {
    request_id: String,
    task_id: u64,
    status: String,
    provider_request_id: Option<String>,
    provenance_schema_version: Option<String>,
    provenance_fingerprint: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    adapter: Option<String>,
    agent_protocol: Option<String>,
    compliance_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AuditExportIndex {
    version: u8,
    total_records: usize,
    by_task_id: BTreeMap<String, Vec<usize>>,
    by_provider: BTreeMap<String, Vec<usize>>,
    by_model: BTreeMap<String, Vec<usize>>,
    by_agent_protocol: BTreeMap<String, Vec<usize>>,
    by_provenance_fingerprint: BTreeMap<String, Vec<usize>>,
}

fn build_audit_export_index(exports: &[EnterpriseAuditExportRecord]) -> AuditExportIndex {
    let mut by_task_id = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provider = BTreeMap::<String, Vec<usize>>::new();
    let mut by_model = BTreeMap::<String, Vec<usize>>::new();
    let mut by_agent_protocol = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provenance_fingerprint = BTreeMap::<String, Vec<usize>>::new();

    for (idx, rec) in exports.iter().enumerate() {
        by_task_id
            .entry(rec.task_id.to_string())
            .or_default()
            .push(idx);

        if let Some(provider) = normalized_optional_field(rec.provider.as_deref()) {
            by_provider.entry(provider).or_default().push(idx);
        }

        if let Some(model) = normalized_optional_field(rec.model.as_deref()) {
            by_model.entry(model).or_default().push(idx);
        }

        if let Some(agent_protocol) = normalized_agent_protocol(rec.agent_protocol.as_deref()) {
            by_agent_protocol.entry(agent_protocol).or_default().push(idx);
        }

        if let Some(fingerprint) =
            normalized_provenance_label(rec.provenance_fingerprint.as_deref(), 128)
                .map(|value| value.to_ascii_lowercase())
        {
            by_provenance_fingerprint
                .entry(fingerprint)
                .or_default()
                .push(idx);
        }
    }

    AuditExportIndex {
        version: 1,
        total_records: exports.len(),
        by_task_id,
        by_provider,
        by_model,
        by_agent_protocol,
        by_provenance_fingerprint,
    }
}

fn audit_export_index_path(output_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.index.json", output_file.display()))
}

fn build_provenance_fingerprint(
    schema_version: Option<&str>,
    provider: Option<&str>,
    model: Option<&str>,
    adapter: Option<&str>,
    agent_protocol: Option<&str>,
    compliance_profile: Option<&str>,
) -> Option<String> {
    let schema = schema_version?;
    let has_any_provenance_label = provider.is_some()
        || model.is_some()
        || adapter.is_some()
        || agent_protocol.is_some()
        || compliance_profile.is_some();
    if !has_any_provenance_label {
        return None;
    }

    let material = format!(
        "schema={};provider={};model={};adapter={};agent_protocol={};compliance_profile={}",
        schema,
        provider.unwrap_or("-"),
        model.unwrap_or("-"),
        adapter.unwrap_or("-"),
        agent_protocol.unwrap_or("-"),
        compliance_profile.unwrap_or("-")
    );
    let mut h = Sha256::new();
    h.update(material.as_bytes());
    Some(hex::encode(h.finalize()))
}

fn normalized_schema_version(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let alias_key: String = normalized
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    match alias_key.as_str() {
        "llmv1" | "llm1" => Some("llm.v1".to_string()),
        "llmv2" | "llm2" => Some("llm.v2".to_string()),
        _ => None,
    }
}

fn to_enterprise_audit_export(rec: &MessageIngressRecord) -> EnterpriseAuditExportRecord {
    let provenance = rec.llm_provenance.as_ref();
    let schema_version = normalized_schema_version(rec.provenance_schema_version.as_deref());
    let is_v2 = schema_version.as_deref() == Some("llm.v2");

    // Re-normalize persisted provenance to fail-closed on legacy/corrupt snapshots.
    let provider = normalized_provenance_label(
        provenance.and_then(|p| p.provider.as_deref()),
        64,
    );
    let model = normalized_provenance_label(
        provenance.and_then(|p| p.model.as_deref()),
        128,
    );
    let adapter = normalized_provenance_label(
        provenance.and_then(|p| p.adapter.as_deref()),
        64,
    );
    let agent_protocol = is_v2
        .then(|| normalized_agent_protocol(provenance.and_then(|p| p.agent_protocol.as_deref())))
        .flatten();
    let compliance_profile = is_v2
        .then(|| {
            normalized_compliance_profile(provenance.and_then(|p| p.compliance_profile.as_deref()))
        })
        .flatten();

    let provenance_fingerprint = build_provenance_fingerprint(
        schema_version.as_deref(),
        provider.as_deref(),
        model.as_deref(),
        adapter.as_deref(),
        agent_protocol.as_deref(),
        compliance_profile.as_deref(),
    );

    EnterpriseAuditExportRecord {
        request_id: rec.request_id.clone(),
        task_id: rec.task_id,
        status: rec.status.clone(),
        provider_request_id: rec.provider_request_id.clone(),
        provenance_schema_version: schema_version,
        provenance_fingerprint,
        provider,
        model,
        adapter,
        agent_protocol,
        compliance_profile,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditExportFormat {
    Jsonl,
    Markdown,
}

fn detect_audit_export_format(path: &Path) -> AuditExportFormat {
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("markdown"))
        .unwrap_or(false)
    {
        AuditExportFormat::Markdown
    } else {
        AuditExportFormat::Jsonl
    }
}

fn markdown_escape(value: Option<&str>) -> String {
    value
        .unwrap_or("-")
        .replace(['\r', '\n'], " ")
        .replace('|', "\\|")
}

fn render_enterprise_audit_markdown(exports: &[EnterpriseAuditExportRecord]) -> String {
    let mut out = String::from(
        "| request_id | task_id | status | provider_request_id | provenance_schema_version | provenance_fingerprint | provider | model | adapter | agent_protocol | compliance_profile |\n",
    );
    out.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );

    for rec in exports {
        let row = format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_escape(Some(rec.request_id.as_str())),
            rec.task_id,
            markdown_escape(Some(rec.status.as_str())),
            markdown_escape(rec.provider_request_id.as_deref()),
            markdown_escape(rec.provenance_schema_version.as_deref()),
            markdown_escape(rec.provenance_fingerprint.as_deref()),
            markdown_escape(rec.provider.as_deref()),
            markdown_escape(rec.model.as_deref()),
            markdown_escape(rec.adapter.as_deref()),
            markdown_escape(rec.agent_protocol.as_deref()),
            markdown_escape(rec.compliance_profile.as_deref()),
        );
        out.push_str(&row);
    }

    out
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
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED | RC_SLO_VIOLATION)
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
    matches!(
        c,
        '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZERO WIDTH NON-JOINER
            | '\u{200D}' // ZERO WIDTH JOINER
            | '\u{200E}' // LEFT-TO-RIGHT MARK
            | '\u{200F}' // RIGHT-TO-LEFT MARK
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
            | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
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

fn normalized_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn normalized_provider_request_id(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?;
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if is_allowed && normalized.len() <= 128 {
        Some(normalized)
    } else {
        None
    }
}

fn normalized_provenance_label(value: Option<&str>, max_len: usize) -> Option<String> {
    let normalized = normalized_optional_field(value)?;
    let has_disallowed_chars = normalized.chars().any(|c| {
        c.is_control() || is_invisible_filler(c) || !c.is_ascii() || c.is_ascii_control()
    });
    if !has_disallowed_chars && normalized.len() <= max_len {
        Some(normalized)
    } else {
        None
    }
}

fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
    let normalized = normalized_optional_field(value)?.to_ascii_lowercase();
    let has_disallowed_chars = normalized
        .chars()
        .any(|c| c.is_control() || is_invisible_filler(c) || !c.is_ascii());
    if has_disallowed_chars {
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
        | "openaimcp"
        | "openaimcpprotocol"
        | "anthropicmcp"
        | "anthropicmcpprotocol" => Some("mcp".to_string()),
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
        | "googlea2a"
        | "googlea2aprotocol"
        | "googleagenttoagent"
        | "googleagenttoagentprotocol" => Some("a2a".to_string()),
        _ => None,
    }
}

fn normalized_compliance_profile(value: Option<&str>) -> Option<String> {
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
    let is_allowed = normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | '/' | '\\'));
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
                .map(|c| if matches!(c, '_' | '.' | '/' | '\\') { '-' } else { c })
                .collect(),
        )
    } else {
        None
    }
}

fn attach_llm_provenance(rec: &mut MessageIngressRecord, llm: &LlmAdapterResponse) {
    rec.provider_request_id = normalized_provider_request_id(llm.provider_request_id.as_deref());

    let provider = normalized_provenance_label(llm.provider.as_deref(), 64);
    let model = normalized_provenance_label(llm.model.as_deref(), 128);
    let adapter = normalized_provenance_label(llm.adapter.as_deref(), 64);
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
        assert!(is_deterministic_rejection(RC_SLO_VIOLATION));
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
    fn llm_adapter_rejects_stdout_without_any_json_line() {
        let cmd = "printf 'debug: adapter warmup\\nstatus=ok\\n'";
        let err = run_llm_adapter_once("sh -lc", cmd, Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
        assert!(err.context.contains("no-json-line"));
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
    fn market_verification_reputation_tiers_remain_strictly_ordered() {
        let accepted = reputation_delta(ReputationSignal::Accepted);
        let retryable = reputation_delta(ReputationSignal::AdapterRetryExhausted);
        let verifier_rejected = reputation_delta(ReputationSignal::VerifierRejected);
        let non_retriable = reputation_delta(ReputationSignal::AdapterNonRetriable);

        assert!(accepted > 0, "accepted work must remain net-positive");
        assert!(retryable < 0, "retry exhaustion must remain a penalty");
        assert!(
            accepted > retryable && retryable > verifier_rejected && verifier_rejected > non_retriable,
            "expected strict tiering: accepted > retryable > verifier_rejected > non_retriable"
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

        // Zero-width/invisible fillers should not pass verifier checks as meaningful output.
        assert_eq!(
            verify_model_output("\u{200B}\u{200C}\u{FEFF}", 8),
            ("rejected", "empty_output")
        );
        assert_eq!(verify_model_output("\u{2060}\u{00AD}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{2061}\u{2062}\u{2063}\u{2064}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{2066}\u{2067}\u{2068}\u{2069}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{034F}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{180E}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{200E}\u{200F}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{FE0E}", 8), ("rejected", "empty_output"));
        assert_eq!(verify_model_output("\u{FE0F}", 8), ("rejected", "empty_output"));

        // Whitespace + zero-width-only payloads must also be rejected deterministically.
        assert_eq!(
            verify_model_output("\n\u{200B} \t\u{200D}\r\n", 8),
            ("rejected", "empty_output")
        );

        // Control-only payloads should not pass market verification as meaningful content.
        assert_eq!(verify_model_output("\u{0007}\u{001B}", 8), ("rejected", "empty_output"));

        // Control bytes mixed around visible content should be ignored for length accounting.
        assert_eq!(verify_model_output("\u{0007}ok\u{001B}", 2), ("accepted", "ok"));

        // Limit is measured in characters (not bytes) to keep verifier behavior predictable.
        let within = "你好ab"; // 4 chars
        assert_eq!(verify_model_output(within, 4), ("accepted", "ok"));

        let over = "你好abc"; // 5 chars
        assert_eq!(verify_model_output(over, 4), ("rejected", "output_too_long"));

        // Leading/trailing transport whitespace should not cause false rejections.
        assert_eq!(verify_model_output(" 你好ab \n", 4), ("accepted", "ok"));

        // Mixed visible + zero-width should still count as meaningful content.
        assert_eq!(verify_model_output("\u{200B}ok\u{200D}", 4), ("accepted", "ok"));

        // Invisible fillers should not inflate length checks for market verification.
        assert_eq!(verify_model_output("\u{200B}ok\u{200D}", 2), ("accepted", "ok"));
        assert_eq!(verify_model_output("o\u{034F}k", 2), ("accepted", "ok"));

        // Direction/isolation wrappers should not alter verifiable length accounting.
        assert_eq!(verify_model_output("\u{2066}ok\u{2069}", 2), ("accepted", "ok"));
        assert_eq!(verify_model_output("\u{2066}ok\u{2069}", 1), ("rejected", "output_too_long"));

        // ZWJ inside visible emoji sequences should stay deterministic for verifier limits.
        assert_eq!(verify_model_output("👩\u{200D}💻", 2), ("accepted", "ok"));
        assert_eq!(verify_model_output("👩\u{200D}💻", 1), ("rejected", "output_too_long"));
    }

    #[test]
    fn exp_backoff_delay_saturates_without_overflow() {
        assert_eq!(exp_backoff_delay_ms(25, 0), 25);
        assert_eq!(exp_backoff_delay_ms(25, 1), 50);
        assert_eq!(exp_backoff_delay_ms(25, 2), 100);

        // Very large attempts should saturate rather than overflow/panic.
        assert_eq!(exp_backoff_delay_ms(u64::MAX, 1), u64::MAX);
        assert_eq!(exp_backoff_delay_ms(1_000_000, 62), u64::MAX);
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
    fn enterprise_audit_export_flattens_v2_provenance_for_agent_and_compliance() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v2".to_string(),
            task_id: 701,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v2".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-701".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-pii-restricted".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.request_id, "r-audit-v2");
        assert_eq!(export.task_id, 701);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );
        assert_eq!(export.provider.as_deref(), Some("openai"));
        let expected = build_provenance_fingerprint(
            Some("llm.v2"),
            Some("openai"),
            Some("gpt-5.3-codex"),
            Some("mcp"),
            Some("a2a"),
            Some("cn-pii-restricted"),
        );
        assert_eq!(export.provenance_fingerprint, expected);
    }

    #[test]
    fn enterprise_audit_export_accepts_case_and_whitespace_drift_for_v2_schema() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v2-drift".to_string(),
            task_id: 7011,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v2-drift".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-7011".to_string()),
            provenance_schema_version: Some("  LLM.V2  ".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-pii-restricted".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );

        let expected = build_provenance_fingerprint(
            Some("llm.v2"),
            Some("openai"),
            Some("gpt-5.3-codex"),
            Some("mcp"),
            Some("a2a"),
            Some("cn-pii-restricted"),
        );
        assert_eq!(export.provenance_fingerprint, expected);
    }

    #[test]
    fn enterprise_audit_export_accepts_separator_aliases_for_schema_version() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v2-alias".to_string(),
            task_id: 70115,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v2-alias".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-70115".to_string()),
            provenance_schema_version: Some("LLM_V2".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-pii-restricted".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );

        let mut compact_alias = rec.clone();
        compact_alias.provenance_schema_version = Some("llm2".to_string());
        let compact_export = to_enterprise_audit_export(&compact_alias);
        assert_eq!(compact_export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(compact_export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            compact_export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn enterprise_audit_export_re_normalizes_legacy_persisted_provenance_fields() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v2-legacy-provenance".to_string(),
            task_id: 7012,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v2-legacy-provenance".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-7012".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("  openai  ".to_string()),
                model: Some("  gpt-5.3-codex  ".to_string()),
                adapter: Some("mcp\ninvalid".to_string()),
                agent_protocol: Some(" Agent-to-Agent v2 ".to_string()),
                compliance_profile: Some(" CN_PII/RESTRICTED ".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(export.provider.as_deref(), Some("openai"));
        assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(export.adapter, None);
        assert_eq!(export.agent_protocol.as_deref(), Some("a2a"));
        assert_eq!(
            export.compliance_profile.as_deref(),
            Some("cn-pii-restricted")
        );

        let expected = build_provenance_fingerprint(
            Some("llm.v2"),
            Some("openai"),
            Some("gpt-5.3-codex"),
            None,
            Some("a2a"),
            Some("cn-pii-restricted"),
        );
        assert_eq!(export.provenance_fingerprint, expected);
    }

    #[test]
    fn enterprise_audit_export_drops_v2_only_fields_when_schema_is_not_v2() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v1-with-v2-fields".to_string(),
            task_id: 702,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v1-with-v2-fields".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-702".to_string()),
            provenance_schema_version: Some("llm.v1".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-pii-restricted".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v1"));
        assert_eq!(export.provider.as_deref(), Some("openai"));
        assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(export.adapter.as_deref(), Some("mcp"));
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
        let expected = build_provenance_fingerprint(
            Some("llm.v1"),
            Some("openai"),
            Some("gpt-5.3-codex"),
            Some("mcp"),
            None,
            None,
        );
        assert_eq!(export.provenance_fingerprint, expected);
    }

    #[test]
    fn enterprise_audit_export_keeps_backward_compat_when_provenance_absent() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-legacy".to_string(),
            task_id: 702,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-legacy".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: None,
            assigned_at_unix_ms: None,
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

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.request_id, "r-audit-legacy");
        assert_eq!(export.provenance_schema_version, None);
        assert_eq!(export.provenance_fingerprint, None);
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
        assert_eq!(export.provider, None);
    }

    #[test]
    fn enterprise_audit_export_gates_fingerprint_when_schema_exists_without_labels() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-v2-empty".to_string(),
            task_id: 703,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-v2-empty".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-703".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: None,
                model: None,
                adapter: None,
                agent_protocol: None,
                compliance_profile: None,
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version.as_deref(), Some("llm.v2"));
        assert_eq!(export.provenance_fingerprint, None);
        assert_eq!(export.provider, None);
        assert_eq!(export.model, None);
        assert_eq!(export.adapter, None);
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
    }

    #[test]
    fn enterprise_audit_export_fail_closed_on_noncanonical_schema_tag() {
        let rec = MessageIngressRecord {
            request_id: "r-audit-bad-schema".to_string(),
            task_id: 7031,
            channel: "telegram".to_string(),
            user_id: "u1".to_string(),
            session_id: "s1".to_string(),
            text: "hello".to_string(),
            idempotency_key: "ik-audit-bad-schema".to_string(),
            status: RequestStatus::Assigned.as_str().to_string(),
            created_at_unix_ms: 1,
            assigned_worker: Some("worker-1".to_string()),
            assigned_at_unix_ms: Some(2),
            model_output: None,
            provider_request_id: Some("provider-7031".to_string()),
            provenance_schema_version: Some("llm.v2-beta".to_string()),
            llm_provenance: Some(LlmProvenanceRecord {
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-pii-restricted".to_string()),
            }),
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
            adapter_error: None,
            reputation_delta: None,
        };

        let export = to_enterprise_audit_export(&rec);
        assert_eq!(export.provenance_schema_version, None);
        assert_eq!(export.provenance_fingerprint, None);
        assert_eq!(export.provider.as_deref(), Some("openai"));
        assert_eq!(export.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(export.adapter.as_deref(), Some("mcp"));
        assert_eq!(export.agent_protocol, None);
        assert_eq!(export.compliance_profile, None);
    }

    #[test]
    fn export_audit_detects_markdown_output_extension() {
        assert_eq!(
            detect_audit_export_format(Path::new("audit-export.md")),
            AuditExportFormat::Markdown
        );
        assert_eq!(
            detect_audit_export_format(Path::new("audit-export.markdown")),
            AuditExportFormat::Markdown
        );
        assert_eq!(
            detect_audit_export_format(Path::new("audit-export.jsonl")),
            AuditExportFormat::Jsonl
        );
    }

    #[test]
    fn export_audit_markdown_contains_provenance_fingerprint_fields() {
        let rows = vec![EnterpriseAuditExportRecord {
            request_id: "r1".to_string(),
            task_id: 7,
            status: "reveal_submitted".to_string(),
            provider_request_id: Some("req-1".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("deadbeef".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }];

        let md = render_enterprise_audit_markdown(&rows);
        assert!(md.contains("| provenance_schema_version | provenance_fingerprint |"));
        assert!(md.contains("| r1 | 7 | reveal_submitted | req-1 | llm.v2 | deadbeef |"));
    }

    #[test]
    fn export_audit_markdown_normalizes_multiline_cells_to_single_line() {
        let rows = vec![EnterpriseAuditExportRecord {
            request_id: "r\n1".to_string(),
            task_id: 8,
            status: "reveal\r\nsubmitted".to_string(),
            provider_request_id: Some("req|2".to_string()),
            provenance_schema_version: Some("llm.v2".to_string()),
            provenance_fingerprint: Some("cafebabe".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some("a2a".to_string()),
            compliance_profile: Some("cn-pii-restricted".to_string()),
        }];

        let md = render_enterprise_audit_markdown(&rows);
        assert!(md.contains("| r 1 | 8 | reveal  submitted | req\\|2 | llm.v2 | cafebabe |"));
        assert!(!md.contains("r\n1"));
        assert!(!md.contains("reveal\r\nsubmitted"));
    }


    #[test]
    fn export_audit_index_contains_task_provider_model_and_fingerprint_keys() {
        let rows = vec![
            EnterpriseAuditExportRecord {
                request_id: "r1".to_string(),
                task_id: 7001,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p1".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("fp-abc".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r2".to_string(),
                task_id: 7002,
                status: "rejected".to_string(),
                provider_request_id: Some("p2".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("fp-abc".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
        ];

        let index = build_audit_export_index(&rows);
        assert_eq!(index.total_records, 2);
        assert_eq!(index.by_task_id.get("7001"), Some(&vec![0]));
        assert_eq!(index.by_task_id.get("7002"), Some(&vec![1]));
        assert_eq!(index.by_provider.get("openai"), Some(&vec![0, 1]));
        assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0, 1]));
        assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
        assert_eq!(index.by_provenance_fingerprint.get("fp-abc"), Some(&vec![0, 1]));
    }

    #[test]
    fn export_audit_index_trims_and_drops_blank_provider_model_or_fingerprint_values() {
        let rows = vec![
            EnterpriseAuditExportRecord {
                request_id: "r1".to_string(),
                task_id: 7101,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p1".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("  fp-xyz  ".to_string()),
                provider: Some("  openai  ".to_string()),
                model: Some("  gpt-5.3-codex  ".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r2".to_string(),
                task_id: 7102,
                status: "rejected".to_string(),
                provider_request_id: Some("p2".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("   ".to_string()),
                provider: Some("   ".to_string()),
                model: Some("\t".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
        ];

        let index = build_audit_export_index(&rows);
        assert_eq!(index.by_provider.get("openai"), Some(&vec![0]));
        assert_eq!(index.by_model.get("gpt-5.3-codex"), Some(&vec![0]));
        assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0, 1]));
        assert_eq!(index.by_provenance_fingerprint.get("fp-xyz"), Some(&vec![0]));
        assert!(!index.by_provider.contains_key(""));
        assert!(!index.by_model.contains_key(""));
        assert!(!index.by_agent_protocol.contains_key(""));
        assert!(!index.by_provenance_fingerprint.contains_key(""));
    }

    #[test]
    fn export_audit_index_normalizes_uppercase_fingerprint_variants() {
        let rows = vec![
            EnterpriseAuditExportRecord {
                request_id: "r1".to_string(),
                task_id: 7201,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p1".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("DEADBEEF".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r2".to_string(),
                task_id: 7202,
                status: "rejected".to_string(),
                provider_request_id: Some("p2".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("deadbeef".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
        ];

        let index = build_audit_export_index(&rows);
        assert_eq!(index.by_provenance_fingerprint.get("deadbeef"), Some(&vec![0, 1]));
        assert!(!index.by_provenance_fingerprint.contains_key("DEADBEEF"));
    }

    #[test]
    fn export_audit_index_normalizes_agent_protocol_aliases_to_canonical_keys() {
        let rows = vec![
            EnterpriseAuditExportRecord {
                request_id: "r1".to_string(),
                task_id: 7251,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p1".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("fp-1".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("A2A-JSON-RPC-V2".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r2".to_string(),
                task_id: 7252,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p2".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("fp-2".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some(" model-context-protocol / stdio v1 ".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
        ];

        let index = build_audit_export_index(&rows);
        assert_eq!(index.by_agent_protocol.get("a2a"), Some(&vec![0]));
        assert_eq!(index.by_agent_protocol.get("mcp"), Some(&vec![1]));
        assert!(!index.by_agent_protocol.contains_key("A2A-JSON-RPC-V2"));
        assert!(!index
            .by_agent_protocol
            .contains_key("model-context-protocol / stdio v1"));
    }

    #[test]
    fn export_audit_index_drops_non_ascii_or_controlled_fingerprints() {
        let rows = vec![
            EnterpriseAuditExportRecord {
                request_id: "r1".to_string(),
                task_id: 7301,
                status: "reveal_submitted".to_string(),
                provider_request_id: Some("p1".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("deadbeef".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r2".to_string(),
                task_id: 7302,
                status: "rejected".to_string(),
                provider_request_id: Some("p2".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("de\u{200b}adbeef".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
            EnterpriseAuditExportRecord {
                request_id: "r3".to_string(),
                task_id: 7303,
                status: "rejected".to_string(),
                provider_request_id: Some("p3".to_string()),
                provenance_schema_version: Some("llm.v2".to_string()),
                provenance_fingerprint: Some("cafébabe".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                adapter: Some("mcp".to_string()),
                agent_protocol: Some("a2a".to_string()),
                compliance_profile: Some("cn-moderate".to_string()),
            },
        ];

        let index = build_audit_export_index(&rows);
        assert_eq!(index.by_provenance_fingerprint.get("deadbeef"), Some(&vec![0]));
        assert_eq!(index.by_provenance_fingerprint.len(), 1);
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
    fn attach_llm_provenance_rejects_non_canonical_provider_request_id() {
        let mut rec = MessageIngressRecord {
            request_id: "r1b".to_string(),
            task_id: 901,
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
            provider_request_id: Some("provider-123\nmal".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: None,
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id, None);
        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
        assert!(rec.llm_provenance.is_some());
    }

    #[test]
    fn normalized_provider_request_id_accepts_boundary_and_rejects_overflow() {
        let ok = "a".repeat(128);
        assert_eq!(
            normalized_provider_request_id(Some(&ok)).as_deref(),
            Some(ok.as_str())
        );

        let overflow = "a".repeat(129);
        assert_eq!(normalized_provider_request_id(Some(&overflow)), None);
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
    fn attach_llm_provenance_drops_overlong_and_controlled_v1_labels() {
        let mut rec = MessageIngressRecord {
            request_id: "r4b".to_string(),
            task_id: 120,
            channel: "telegram".to_string(),
            user_id: "u4".to_string(),
            session_id: "s4".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik4b".to_string(),
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
            provider_request_id: Some("provider-4b".to_string()),
            provider: Some("p".repeat(65)),
            model: Some(format!("model-{}", "x".repeat(140))),
            adapter: Some("mcp\nrelay".to_string()),
            agent_protocol: None,
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4b"));
        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_rejects_invisible_fillers_in_v1_labels() {
        let mut rec = MessageIngressRecord {
            request_id: "r4c".to_string(),
            task_id: 121,
            channel: "telegram".to_string(),
            user_id: "u4".to_string(),
            session_id: "s4".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik4c".to_string(),
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
            provider_request_id: Some("provider-4c".to_string()),
            provider: Some("open\u{200b}ai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: None,
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provider_request_id.as_deref(), Some("provider-4c"));
        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.provider, None);
        assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(prov.adapter.as_deref(), Some("mcp"));
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
    fn attach_llm_provenance_accepts_agent_protocol_aliases() {
        let mut rec = MessageIngressRecord {
            request_id: "r5a".to_string(),
            task_id: 130,
            channel: "telegram".to_string(),
            user_id: "u5".to_string(),
            session_id: "s5".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik5a".to_string(),
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
            agent_protocol: Some("  Model-Context Protocol  ".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v2"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("MCP v2".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("mcp"));

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("Agent/2/Agent".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("A2A v1".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("agent-to-agent".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("Agent 2 Agent Protocol".to_string()),
            compliance_profile: None,
        };

        attach_llm_provenance(&mut rec, &llm);

        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.agent_protocol.as_deref(), Some("a2a"));
    }

    #[test]
    fn normalized_agent_protocol_accepts_punctuation_variants_for_aliases() {
        assert_eq!(
            normalized_agent_protocol(Some("Model.Context.Protocol")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Model Context Protocol 2.0")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Model Context Protocol JSON-RPC v2")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Agent:To:Agent")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Agent-To-Agent Protocol v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("A2A 2.0")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("A2A JSON-RPC v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Agent-to-Agent JSON-RPC v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Agent-2-Agent Protocol JSON-RPC v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Model Context Protocol STDIO v2")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("MCP over JSON-RPC v2")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("MCP over STDIO v2")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Agent-to-Agent Protocol STDIO v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("A2A over JSON-RPC v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("A2A over STDIO v2")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("OpenAI MCP")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Anthropic MCP Protocol")).as_deref(),
            Some("mcp")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Google A2A")).as_deref(),
            Some("a2a")
        );
        assert_eq!(
            normalized_agent_protocol(Some("Google Agent-to-Agent Protocol")).as_deref(),
            Some("a2a")
        );
    }

    #[test]
    fn attach_llm_provenance_rejects_non_ascii_or_invisible_agent_protocol_aliases() {
        let mut rec = MessageIngressRecord {
            request_id: "r5aa".to_string(),
            task_id: 1301,
            channel: "telegram".to_string(),
            user_id: "u5".to_string(),
            session_id: "s5".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik5aa".to_string(),
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
            agent_protocol: Some("MCP🔥".to_string()),
            compliance_profile: None,
        };
        attach_llm_provenance(&mut rec, &llm);
        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());

        let llm = LlmAdapterResponse {
            output_text: "ok".to_string(),
            provider_request_id: None,
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: Some("a2a\u{200b}".to_string()),
            compliance_profile: None,
        };
        attach_llm_provenance(&mut rec, &llm);
        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
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
    fn attach_llm_provenance_keeps_v1_when_v2_fields_are_invalid() {
        let mut rec = MessageIngressRecord {
            request_id: "r5c".to_string(),
            task_id: 132,
            channel: "telegram".to_string(),
            user_id: "u5".to_string(),
            session_id: "s5".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik5c".to_string(),
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
            provider_request_id: Some("prid-2".to_string()),
            provider: Some("openai".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            adapter: Some("mcp".to_string()),
            agent_protocol: Some(" custom-proto ".to_string()),
            compliance_profile: Some("CN@PII@Restricted".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version.as_deref(), Some("llm.v1"));
        let prov = rec.llm_provenance.as_ref().expect("provenance attached");
        assert_eq!(prov.provider.as_deref(), Some("openai"));
        assert_eq!(prov.model.as_deref(), Some("gpt-5.3-codex"));
        assert_eq!(prov.adapter.as_deref(), Some("mcp"));
        assert_eq!(prov.agent_protocol, None);
        assert_eq!(prov.compliance_profile, None);
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
    fn attach_llm_provenance_normalizes_space_separated_compliance_profile() {
        let mut rec = MessageIngressRecord {
            request_id: "r6-space".to_string(),
            task_id: 142,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6-space".to_string(),
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
            compliance_profile: Some("CN PII Restricted".to_string()),
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
            compliance_profile: Some("CN@PII@Restricted".to_string()),
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
    fn attach_llm_provenance_rejects_repeated_separators_in_compliance_profile() {
        let mut rec = MessageIngressRecord {
            request_id: "r6d".to_string(),
            task_id: 143,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6d".to_string(),
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
            provider_request_id: Some("provider-6d".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: Some("cn--pii__restricted".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn attach_llm_provenance_rejects_mixed_adjacent_separators_in_compliance_profile() {
        let mut rec = MessageIngressRecord {
            request_id: "r6e".to_string(),
            task_id: 144,
            channel: "telegram".to_string(),
            user_id: "u6".to_string(),
            session_id: "s6".to_string(),
            text: "prompt".to_string(),
            idempotency_key: "ik6e".to_string(),
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
            provider_request_id: Some("provider-6e".to_string()),
            provider: None,
            model: None,
            adapter: None,
            agent_protocol: None,
            compliance_profile: Some("cn-_pii-restricted".to_string()),
        };

        attach_llm_provenance(&mut rec, &llm);

        assert_eq!(rec.provenance_schema_version, None);
        assert!(rec.llm_provenance.is_none());
    }

    #[test]
    fn normalized_compliance_profile_accepts_64_char_boundary() {
        let profile = format!("{}-{}", "a".repeat(31), "b".repeat(32));
        assert_eq!(profile.len(), 64);
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

    #[test]
    fn normalized_compliance_profile_rejects_numeric_only_values() {
        assert_eq!(normalized_compliance_profile(Some("202602")), None);
    }

    #[test]
    fn normalized_compliance_profile_rejects_single_token_values() {
        assert_eq!(normalized_compliance_profile(Some("restricted")), None);
    }

    #[test]
    fn normalized_compliance_profile_accepts_alphanumeric_when_contains_alpha() {
        assert_eq!(
            normalized_compliance_profile(Some("cn-202602"))
                .as_deref(),
            Some("cn-202602")
        );
    }

    #[test]
    fn normalized_compliance_profile_accepts_dot_separators_and_normalizes_to_hyphen() {
        assert_eq!(
            normalized_compliance_profile(Some("CN.PII.Restricted")).as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn normalized_compliance_profile_accepts_slash_separators_and_normalizes_to_hyphen() {
        assert_eq!(
            normalized_compliance_profile(Some("CN/PII/Restricted")).as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn normalized_compliance_profile_accepts_backslash_separators_and_normalizes_to_hyphen() {
        assert_eq!(
            normalized_compliance_profile(Some("CN\\PII\\Restricted")).as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn normalized_compliance_profile_accepts_space_separators_and_normalizes_to_hyphen() {
        assert_eq!(
            normalized_compliance_profile(Some("CN PII Restricted")).as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_adjacent_space_separators() {
        assert_eq!(
            normalized_compliance_profile(Some("cn  pii restricted")),
            None
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_control_whitespace_separators() {
        assert_eq!(
            normalized_compliance_profile(Some("cn\tpii restricted")),
            None
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_adjacent_dot_separators() {
        assert_eq!(
            normalized_compliance_profile(Some("cn..pii.restricted")),
            None
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_adjacent_mixed_path_separators() {
        assert_eq!(
            normalized_compliance_profile(Some("cn\\/pii-restricted")),
            None
        );
    }

    #[test]
    fn normalized_compliance_profile_rejects_values_starting_with_digit() {
        assert_eq!(
            normalized_compliance_profile(Some("1cn-pii-restricted")),
            None
        );
    }

    #[test]
    fn normalized_compliance_profile_canonicalizes_underscore_to_hyphen() {
        assert_eq!(
            normalized_compliance_profile(Some("CN_PII_RESTRICTED")).as_deref(),
            Some("cn-pii-restricted")
        );
    }

    #[test]
    fn normalized_provenance_label_accepts_ascii_audit_text() {
        assert_eq!(
            normalized_provenance_label(Some("openai gpt-5.3:preview"), 64).as_deref(),
            Some("openai gpt-5.3:preview")
        );
    }

    #[test]
    fn normalized_provenance_label_rejects_non_ascii_homoglyphs() {
        assert_eq!(
            normalized_provenance_label(Some("оpenai"), 64),
            None,
            "non-ascii provenance labels should be rejected to avoid audit ambiguity"
        );
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
                let proof_adapter = StandardProofAdapter;
                let (verified, resolution_code) =
                    proof_adapter.verify(&llm.output_text, verifier_max_output_chars);
                let v_status = if verified { "accepted" } else { "rejected" };
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
        Command::ExportAudit {
            ingress_file,
            output_file,
        } => {
            let records = load_ingress_records(&ingress_file)?;
            let mut exports = Vec::new();

            for rec in records.iter() {
                // Only export finalized or processed requests
                if matches!(
                    rec.status.as_str(),
                    "reveal_submitted" | "rejected" | "failed_submission" | "failed_adapter"
                ) {
                    exports.push(to_enterprise_audit_export(rec));
                }
            }

            if let Some(parent) = output_file.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut file = fs::File::create(&output_file)?;
            match detect_audit_export_format(&output_file) {
                AuditExportFormat::Jsonl => {
                    for export in exports.iter() {
                        let line = serde_json::to_string(export)?;
                        file.write_all(line.as_bytes())?;
                        file.write_all(b"\n")?;
                    }
                }
                AuditExportFormat::Markdown => {
                    file.write_all(render_enterprise_audit_markdown(&exports).as_bytes())?;
                }
            }

            let index = build_audit_export_index(&exports);
            let index_file = audit_export_index_path(&output_file);
            fs::write(&index_file, serde_json::to_string_pretty(&index)?)?;

            println!(
                "[agent] exported audit records={} file={} index_file={} format={:?}",
                exports.len(),
                output_file.display(),
                index_file.display(),
                detect_audit_export_format(&output_file)
            );
        }
    }
    Ok(())
}
