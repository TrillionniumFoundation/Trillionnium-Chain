use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-worker-agent",
    version,
    about = "Trillionnium PoCO worker-agent (MVP skeleton)"
)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
