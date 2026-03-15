use anyhow::{anyhow, Result};
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

use proof_adapter::{build_proof_adapter, ProofAdapter, DEFAULT_PROOF_ADAPTER};
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
const PROOF_ADAPTER_ENV: &str = "TRNM_PROOF_ADAPTER";
const WORKER_EVENT_LOG_ENV: &str = "TRNM_WORKER_EVENT_LOG";
const WORKER_PROGRESS_LOG_ENV: &str = "TRNM_WORKER_PROGRESS_LOG";

const RC_OK: i32 = 0;
const RC_DUPLICATE: i32 = 9;
const RC_NONCE_REJECTED: i32 = 10;
const RC_SLO_VIOLATION: i32 = 11;
const RC_SKIPPED: i32 = -1;

#[derive(Debug, Clone)]
struct PersistedAckHashes {
    commit_tx_hash: Option<String>,
    reveal_tx_hash: Option<String>,
}

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
    QueryAudit {
        #[arg(long, default_value = "audit-export.jsonl")]
        output_file: PathBuf,
        #[arg(long)]
        task_id: Option<u64>,
        #[arg(long)]
        provenance_fingerprint: Option<String>,
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
    by_status: BTreeMap<String, Vec<usize>>,
    by_status_phase: BTreeMap<String, Vec<usize>>,
    by_provider: BTreeMap<String, Vec<usize>>,
    by_model: BTreeMap<String, Vec<usize>>,
    by_agent_protocol: BTreeMap<String, Vec<usize>>,
    by_compliance_profile: BTreeMap<String, Vec<usize>>,
    by_provenance_fingerprint: BTreeMap<String, Vec<usize>>,
}

fn audit_status_phase(status: &str) -> &'static str {
    match status {
        "completed" | "slashed" | "rejected" | "cancelled" => "terminal",
        _ => "active",
    }
}

fn build_audit_export_index(exports: &[EnterpriseAuditExportRecord]) -> AuditExportIndex {
    let mut by_task_id = BTreeMap::<String, Vec<usize>>::new();
    let mut by_status = BTreeMap::<String, Vec<usize>>::new();
    let mut by_status_phase = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provider = BTreeMap::<String, Vec<usize>>::new();
    let mut by_model = BTreeMap::<String, Vec<usize>>::new();
    let mut by_agent_protocol = BTreeMap::<String, Vec<usize>>::new();
    let mut by_compliance_profile = BTreeMap::<String, Vec<usize>>::new();
    let mut by_provenance_fingerprint = BTreeMap::<String, Vec<usize>>::new();

    for (idx, rec) in exports.iter().enumerate() {
        by_task_id
            .entry(rec.task_id.to_string())
            .or_default()
            .push(idx);

        if let Some(status) = normalized_optional_field(Some(rec.status.as_str())) {
            let normalized_status = status.to_ascii_lowercase();
            by_status
                .entry(normalized_status.clone())
                .or_default()
                .push(idx);
            by_status_phase
                .entry(audit_status_phase(&normalized_status).to_string())
                .or_default()
                .push(idx);
        }

        if let Some(provider) = normalized_optional_field(rec.provider.as_deref()) {
            by_provider.entry(provider).or_default().push(idx);
        }

        if let Some(model) = normalized_optional_field(rec.model.as_deref()) {
            by_model.entry(model).or_default().push(idx);
        }

        if let Some(agent_protocol) = normalized_agent_protocol(rec.agent_protocol.as_deref()) {
            by_agent_protocol
                .entry(agent_protocol)
                .or_default()
                .push(idx);
        }

        if let Some(compliance_profile) =
            normalized_compliance_profile(rec.compliance_profile.as_deref())
        {
            by_compliance_profile
                .entry(compliance_profile)
                .or_default()
                .push(idx);
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
        by_status,
        by_status_phase,
        by_provider,
        by_model,
        by_agent_protocol,
        by_compliance_profile,
        by_provenance_fingerprint,
    }
}

fn query_audit_export_by_task_id<'a>(
    exports: &'a [EnterpriseAuditExportRecord],
    index: &AuditExportIndex,
    task_id: u64,
) -> Vec<&'a EnterpriseAuditExportRecord> {
    index
        .by_task_id
        .get(&task_id.to_string())
        .into_iter()
        .flat_map(|rows| rows.iter().filter_map(|idx| exports.get(*idx)))
        .collect()
}

fn normalize_provenance_fingerprint_lookup(value: &str) -> Option<String> {
    let mut normalized =
        trim_boundary_audit_fillers(normalized_optional_field(Some(value))?.as_str()).to_string();

    // Accept heavily shell-escaped forms (e.g., nested quote wrappers from CLI/env propagation)
    // while still fail-closing on empty/invalid labels after normalization.
    // Keep recursive unwrapping bounded, but generous enough to tolerate repeated
    // shell/env forwarding hops seen in automation pipelines.
    for _ in 0..16 {
        let bytes = normalized.as_bytes();
        let mut peeled = false;

        if bytes.len() >= 2
            && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
                || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
                || (bytes[0] == b'`' && bytes[bytes.len() - 1] == b'`'))
        {
            normalized = normalized[1..normalized.len() - 1].trim().to_string();
            peeled = true;
        } else if bytes.len() >= 4
            && bytes[0] == b'\\'
            && bytes[bytes.len() - 2] == b'\\'
            && ((bytes[1] == b'\'' && bytes[bytes.len() - 1] == b'\'')
                || (bytes[1] == b'"' && bytes[bytes.len() - 1] == b'"')
                || (bytes[1] == b'`' && bytes[bytes.len() - 1] == b'`'))
        {
            normalized = normalized[2..normalized.len() - 2].trim().to_string();
            peeled = true;
        }

        if peeled {
            normalized = trim_boundary_audit_fillers(normalized.as_str()).to_string();
            if normalized.is_empty() {
                return None;
            }
            continue;
        }

        break;
    }
    normalized_provenance_label(Some(normalized.as_str()), 128).map(|v| v.to_ascii_lowercase())
}

fn query_audit_export_by_provenance_fingerprint<'a>(
    exports: &'a [EnterpriseAuditExportRecord],
    index: &AuditExportIndex,
    provenance_fingerprint: &str,
) -> Vec<&'a EnterpriseAuditExportRecord> {
    let Some(normalized) = normalize_provenance_fingerprint_lookup(provenance_fingerprint) else {
        return Vec::new();
    };
    index
        .by_provenance_fingerprint
        .get(&normalized)
        .into_iter()
        .flat_map(|rows| rows.iter().filter_map(|idx| exports.get(*idx)))
        .collect()
}

#[derive(Debug, Serialize)]
struct QueryAuditRecord {
    #[serde(flatten)]
    record: EnterpriseAuditExportRecord,
    proof_type: Option<String>,
    settlement_status: String,
    timestamp_unix_ms: Option<u128>,
}

impl From<EnterpriseAuditExportRecord> for QueryAuditRecord {
    fn from(record: EnterpriseAuditExportRecord) -> Self {
        let settlement_status = record.status.clone();
        Self {
            record,
            proof_type: None,
            settlement_status,
            timestamp_unix_ms: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct QueryAuditOutput {
    hit_indexes: Vec<usize>,
    records: Vec<QueryAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance_fingerprint: Option<String>,
}

fn audit_export_index_path(output_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.index.json", output_file.display()))
}

fn validate_audit_export_index(index: &AuditExportIndex, exports_len: usize) -> Result<()> {
    if index.version != 1 {
        anyhow::bail!(
            "unsupported audit index version={} (expected=1)",
            index.version
        );
    }
    if index.total_records != exports_len {
        anyhow::bail!(
            "audit index total_records mismatch: index={} exports={}",
            index.total_records,
            exports_len
        );
    }

    for (label, offsets) in [
        ("by_task_id", &index.by_task_id),
        ("by_status", &index.by_status),
        ("by_status_phase", &index.by_status_phase),
        ("by_provider", &index.by_provider),
        ("by_model", &index.by_model),
        ("by_agent_protocol", &index.by_agent_protocol),
        ("by_compliance_profile", &index.by_compliance_profile),
        (
            "by_provenance_fingerprint",
            &index.by_provenance_fingerprint,
        ),
    ] {
        for (key, rows) in offsets {
            for idx in rows {
                if *idx >= index.total_records {
                    anyhow::bail!(
                        "audit index offset out of bounds: map={} key={} idx={} total_records={}",
                        label,
                        key,
                        idx,
                        index.total_records
                    );
                }
            }
        }
    }

    Ok(())
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
    let provider = normalized_provenance_label(provenance.and_then(|p| p.provider.as_deref()), 64);
    let model = normalized_provenance_label(provenance.and_then(|p| p.model.as_deref()), 128);
    let adapter = normalized_provenance_label(provenance.and_then(|p| p.adapter.as_deref()), 64);
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
        provider_request_id: normalized_provider_request_id(rec.provider_request_id.as_deref()),
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
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

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

fn load_acked(ack_log: &PathBuf) -> HashSet<u64> {
    load_ack_records(ack_log)
        .into_iter()
        .filter(|rec| rec.status == "accepted")
        .map(|rec| rec.task_id)
        .collect()
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

fn resolve_path_arg_from_env(path: PathBuf, env_name: &str, default_path: &str) -> PathBuf {
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

fn normalize_candidate_tx_hash(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || matches!(
                    c,
                    ',' | ';' | '.' | ':' | ')' | ']' | '}' | '>' | '(' | '[' | '{' | '<'
                )
                || c.is_control()
                || is_invisible_filler(c)
        })
        .trim_end_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || matches!(c, ',' | ';' | '}' | ']' | '>')
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
                    || matches!(ch, '(' | '[' | '{' | '<')
            });
            if let Some(rest) = candidate.strip_prefix('\\') {
                if rest
                    .chars()
                    .next()
                    .is_some_and(is_receipt_quote_wrapper)
                {
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

    for haystack in [
        text,
        normalized_key_quotes.as_str(),
        normalized_delimiters.as_str(),
        normalized_whitespace.as_str(),
    ] {
        for prefix in PREFIXES {
            let mut remainder = haystack;
            while let Some(idx) = remainder.find(prefix) {
                let suffix = &remainder[idx + prefix.len()..];
                if let Some(parsed) = parse_hash_from_suffix(suffix) {
                    return Some(parsed);
                }
                remainder = &suffix[1.min(suffix.len())..];
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

fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}

fn persisted_ack_hashes_for_task(ack_log: &PathBuf, task_id: u64) -> PersistedAckHashes {
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

fn backoff_delay_ms(base_ms: u64, attempt: u32) -> u64 {
    base_ms.saturating_mul(attempt as u64 + 1)
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

fn run_adapter_with_retry(
    adapter_cmd: &str,
    action_args: &[String],
    max_retries: u32,
    backoff_ms: u64,
) -> Result<AdapterExecResult> {
    let (program, base_args) = parse_command_spec(adapter_cmd)?;
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = ProcCommand::new(&program)
            .args(&base_args)
            .args(action_args)
            .output()?;
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
        '\u{200B}' // ZERO WIDTH SPACE
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

fn trim_boundary_audit_fillers(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || c.is_control() || is_invisible_filler(c))
}

fn normalized_provider_request_id(value: Option<&str>) -> Option<String> {
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

fn normalized_provenance_label(value: Option<&str>, max_len: usize) -> Option<String> {
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

fn normalized_agent_protocol(value: Option<&str>) -> Option<String> {
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

fn attach_llm_provenance(rec: &mut MessageIngressRecord, llm: &LlmAdapterResponse) {
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

fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
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
mod tests;

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
            let proof_adapter_name = env::var(PROOF_ADAPTER_ENV)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_PROOF_ADAPTER.to_string());
            let proof_adapter = build_proof_adapter(&proof_adapter_name).map_err(|e| {
                anyhow!(
                    "invalid {PROOF_ADAPTER_ENV}={proof_adapter_name:?}: {e}; supported={DEFAULT_PROOF_ADAPTER}"
                )
            })?;
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
                    proof_adapter.as_ref(),
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
                let (verified, resolution_code) =
                    proof_adapter.verify(&llm.output_text, verifier_max_output_chars);
                let v_status = if verified { "accepted" } else { "rejected" };
                attach_llm_provenance(rec, &llm);
                rec.model_output = Some(llm.output_text.clone());
                rec.verifier_status = Some(v_status.to_string());
                rec.resolution_code = Some(resolution_code.to_string());

                if v_status != "accepted" {
                    rec.status = transition_request_status(&rec.status, RequestStatus::Rejected)?;
                    rec.reputation_delta =
                        Some(reputation_delta(ReputationSignal::VerifierRejected));
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
            let event_log = resolve_path_arg_from_env(
                event_log,
                WORKER_EVENT_LOG_ENV,
                "/tmp/trnm-worker-agent-events.jsonl",
            );
            let progress_log = resolve_path_arg_from_env(
                progress_log,
                WORKER_PROGRESS_LOG_ENV,
                "/tmp/trnm-worker-agent-progress.jsonl",
            );
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
                    let commit_args = vec![
                        "commit".to_string(),
                        rec.task_id.to_string(),
                        rec.worker.clone(),
                        rec.commit_hash.clone(),
                        nonce.to_string(),
                    ];
                    let reveal_args = vec![
                        "reveal".to_string(),
                        rec.task_id.to_string(),
                        rec.result_hash.clone(),
                        rec.salt_hex.clone(),
                    ];

                    let commit_res = run_adapter_with_retry(
                        &adapter_cmd,
                        &commit_args,
                        tx_retry.max_retries,
                        tx_retry.backoff_ms,
                    )?;
                    let reveal_executed = should_execute_reveal(&commit_res);
                    let reveal_res = if reveal_executed {
                        run_adapter_with_retry(
                            &adapter_cmd,
                            &reveal_args,
                            tx_retry.max_retries,
                            tx_retry.backoff_ms,
                        )?
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

                    let previous_ack_hashes = persisted_ack_hashes_for_task(&ack_log, rec.task_id);
                    let previous_commit_tx_hash = previous_ack_hashes.commit_tx_hash;
                    let previous_reveal_tx_hash = previous_ack_hashes.reveal_tx_hash;

                    let commit_hash_observed = commit_res.tx_hash.is_some()
                        || (is_idempotent_duplicate_ok(commit_res.rc)
                            && previous_commit_tx_hash.is_some());
                    let reveal_hash_observed = reveal_res.tx_hash.is_some()
                        || (is_idempotent_duplicate_ok(reveal_res.rc)
                            && previous_reveal_tx_hash.is_some());

                    let commit_tx_hash_for_ack =
                        commit_res.tx_hash.clone().or(previous_commit_tx_hash);
                    let reveal_tx_hash_for_ack =
                        reveal_res.tx_hash.clone().or(previous_reveal_tx_hash);

                    let (ack_status, reason_code, ack_reason) = if commit_idempotent_ok
                        && reveal_idempotent_ok
                        && commit_hash_observed
                        && reveal_hash_observed
                    {
                        (
                            "accepted",
                            "idempotent_ok",
                            format!(
                                "idempotent-ok commit_rc={} reveal_rc={}",
                                commit_res.rc, reveal_res.rc
                            ),
                        )
                    } else if commit_idempotent_ok
                        && reveal_idempotent_ok
                        && (!commit_hash_observed || !reveal_hash_observed)
                    {
                        (
                            "failed",
                            "missing_tx_hash_receipt",
                            format!(
                                "missing-tx-hash-receipt commit_tx_hash_present={} reveal_tx_hash_present={} commit_rc={} reveal_rc={}",
                                commit_hash_observed, reveal_hash_observed, commit_res.rc, reveal_res.rc
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
                        commit_tx_hash_for_ack.clone(),
                        reveal_tx_hash_for_ack.clone(),
                        Some(reason_code.to_string()),
                        Some(run_id.clone()),
                    )?;

                    if update_ingress {
                        let mut ingress = load_ingress_records(&ingress_file)?;
                        let mut changed = false;
                        for ir in ingress.iter_mut() {
                            if ir.task_id == rec.task_id {
                                ir.commit_tx_hash = commit_tx_hash_for_ack.clone();
                                ir.reveal_tx_hash = reveal_tx_hash_for_ack.clone();
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
            if let Some(first) = exports.first() {
                let _ = query_audit_export_by_task_id(&exports, &index, first.task_id);
            }
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
        Command::QueryAudit {
            output_file,
            task_id,
            provenance_fingerprint,
        } => {
            if task_id.is_some() == provenance_fingerprint.is_some() {
                return Err(anyhow!(
                    "query-audit requires exactly one filter: --task-id or --provenance-fingerprint"
                ));
            }

            let index_file = audit_export_index_path(&output_file);
            if !index_file.exists() {
                return Err(anyhow!(
                    "query-audit missing index file: {}",
                    index_file.display()
                ));
            }

            if detect_audit_export_format(&output_file) != AuditExportFormat::Jsonl {
                return Err(anyhow!(
                    "query-audit only supports JSONL audit exports: {}",
                    output_file.display()
                ));
            }

            let mut exports = Vec::new();
            for line in fs::read_to_string(&output_file)?.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                exports.push(serde_json::from_str::<EnterpriseAuditExportRecord>(line)?);
            }
            let index: AuditExportIndex = serde_json::from_str(&fs::read_to_string(&index_file)?)?;
            validate_audit_export_index(&index, exports.len())?;

            let (hit_indexes, records, normalized_fp) = if let Some(task_id) = task_id {
                let key = task_id.to_string();
                let hits = index.by_task_id.get(&key).cloned().unwrap_or_default();
                let rows: Vec<EnterpriseAuditExportRecord> =
                    query_audit_export_by_task_id(&exports, &index, task_id)
                        .into_iter()
                        .cloned()
                        .collect();
                (hits, rows, None)
            } else {
                let raw = provenance_fingerprint.expect("checked above");
                let normalized = normalize_provenance_fingerprint_lookup(raw.as_str())
                    .ok_or_else(|| anyhow!("invalid provenance fingerprint filter"))?;
                let hits = index
                    .by_provenance_fingerprint
                    .get(&normalized)
                    .cloned()
                    .unwrap_or_default();
                let rows: Vec<EnterpriseAuditExportRecord> =
                    query_audit_export_by_provenance_fingerprint(&exports, &index, &normalized)
                        .into_iter()
                        .cloned()
                        .collect();
                (hits, rows, Some(normalized))
            };

            let out = QueryAuditOutput {
                hit_indexes,
                records: records.into_iter().map(QueryAuditRecord::from).collect(),
                provenance_fingerprint: normalized_fp,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}
