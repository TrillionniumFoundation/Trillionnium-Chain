use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::io::{Seek, SeekFrom};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_rpc::{
    get_tx, query_account_state, submit_tx, validate_trnm_address, AccountBalanceQueryResponse,
    AccountNonceQueryResponse, AccountState, EventQueryResponse, FaucetRequestResponse, GetTxError,
    GovParamQueryResponse, GovProposalQueryResponse, InMemoryTransferLedger,
    MessageRequestQueryResponse, RequestFullQueryResponse, RpcErrorResponse,
    TaskMeteringDerivedQueryResponse, TaskMeteringPolicyQueryResponse, TaskMeteringQueryResponse,
    TaskQueryResponse, TxLifecycleRecord,
};
use trnm_state::StateStore;
use trnm_types::{
    AuditEvent, CapabilityToken, GovProposalObject, GovProposalStatus, IdentityRegistry,
    PrivacyTier, RequestStatus, TaskMetadata, TaskMeteringSnapshot, TaskObject, TaskStatus,
    TransferTx,
};

const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
const QUERY_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT: usize = 60;
const QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
const QUERY_FULL_LIMIT_MAX: usize = 200;
const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
const DISPATCH_OPEN_LIMIT_MAX: usize = 100;
const CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT: usize = 20;
const CHALLENGE_TREASURY_EVENTS_LIMIT_MAX: usize = 200;
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
#[cfg(test)]
const NODE_EVENT_LOG_TAIL_BYTES_DEFAULT: u64 = 4 * 1024 * 1024;
#[cfg(test)]
const NODE_EVENT_LOG_TAIL_BYTES_MAX: u64 = 16 * 1024 * 1024;
const NODE_EVENT_LOG_SOURCES_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_SOURCES";
const NODE_EVENT_LOG_MANIFEST_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_MANIFEST";
const OPS_WINDOW_CUSTOM_MAX_MS: u128 = 31 * 24 * 60 * 60 * 1000;
const FAUCET_WINDOW_SECONDS_DEFAULT: u64 = 60;
const FAUCET_WINDOW_SECONDS_MIN: u64 = 1;
const FAUCET_MAX_REQUESTS_DEFAULT: u32 = 1;
const FAUCET_MAX_REQUESTS_MIN: u32 = 1;
const EMERGENCY_PAUSE_KEY_ID: u64 = 7_999;
const MARKET_REPUTATION_FILE_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_FILE";
const TASK_STATE_FILE_ENV: &str = "TRNM_RPC_TASK_STATE_FILE";
const MARKET_PRICE_WEIGHT_ENV: &str = "TRNM_RPC_MARKET_PRICE_WEIGHT";
const MARKET_REPUTATION_WEIGHT_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_WEIGHT";
const MARKET_REPUTATION_CLAMP_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_CLAMP";
const MARKET_PRICE_WEIGHT_DEFAULT: u128 = 1_000;
const MARKET_REPUTATION_WEIGHT_DEFAULT: u128 = 100;
const MARKET_REPUTATION_CLAMP_DEFAULT: i64 = 1_000;
const MARKET_WEIGHT_MIN: u128 = 1;
const MARKET_WEIGHT_MAX: u128 = 1_000_000;
const MARKET_REPUTATION_CLAMP_MIN: i64 = 1;
const MARKET_REPUTATION_CLAMP_MAX: i64 = 1_000_000;
const MARKET_LOCK_TIMEOUT_MS_DEFAULT: u64 = 5_000;
const MARKET_LOCK_TIMEOUT_MS_MIN: u64 = 100;
const MARKET_LOCK_TIMEOUT_MS_MAX: u64 = 60_000;
const SUBMIT_MESSAGE_MAX_BYTES_ENV: &str = "TRNM_RPC_SUBMIT_MESSAGE_MAX_BYTES";
const SUBMIT_MESSAGE_MAX_BYTES_DEFAULT: u64 = 256 * 1024;
const HEALTH_SOCKET_READ_TIMEOUT_MS: u64 = 2_000;
const HEALTH_SOCKET_WRITE_TIMEOUT_MS: u64 = 2_000;
const HEALTH_REQUEST_HEADER_MAX_BYTES: usize = 4 * 1024;
const SUBMIT_MESSAGE_MAX_BYTES_MIN: u64 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-rpc",
    version,
    about = "Trillionnium RPC (state-backed query schema)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    QueryTask {
        task_id: u64,
    },
    QueryProposal {
        proposal_id: u64,
    },
    QueryParam {
        key: String,
    },
    QueryEvents {
        task_id: u64,
        #[arg(long, default_value_t = QUERY_EVENTS_LIMIT_DEFAULT)]
        limit: usize,
    },
    QueryCapabilityAudit {
        #[arg(long)]
        token_id: u64,
    },
    /// Query challenge treasury/forfeits current summary and recent related events
    QueryChallengeTreasury {
        #[arg(long, default_value_t = CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT)]
        limit: usize,
        /// Rolling window preset for ops summary (24h / 7d / custom)
        #[arg(long, value_enum)]
        window: Option<OpsWindowArg>,
        /// Start unix timestamp (ms), required when --window custom
        #[arg(long)]
        from_unix_ms: Option<u128>,
        /// End unix timestamp (ms), required when --window custom
        #[arg(long)]
        to_unix_ms: Option<u128>,
        /// Force JSON output (backward-compatible no-op, kept for dashboard scripts)
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    QueryBalance {
        address: String,
    },
    QueryNonce {
        address: String,
    },
    SendTx {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value_t = 0)]
        fee: u128,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        signature: String,
    },
    GetTx {
        #[arg(long)]
        tx_hash: String,
    },
    FaucetRequest {
        #[arg(long)]
        address: String,
        #[arg(long, default_value_t = 1000)]
        amount: u128,
    },
    SubmitMessage {
        #[arg(long)]
        channel: String,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        idempotency_key: String,
    },
    QueryRequest {
        #[arg(long)]
        request_id: String,
    },
    QueryRequestFull {
        #[arg(long)]
        request_id: String,
        #[arg(long, default_value_t = QUERY_FULL_LIMIT_DEFAULT)]
        limit: usize,
    },
    #[command(name = "market.create_task", visible_alias = "market-create-task")]
    MarketCreateTask {
        #[arg(long)]
        creator: String,
        #[arg(long)]
        bounty: u128,
        #[arg(long)]
        description: String,
    },
    #[command(name = "market.submit_bid", visible_alias = "market-submit-bid")]
    MarketSubmitBid {
        #[arg(long)]
        task_id: u64,
        #[arg(long)]
        worker: String,
        #[arg(long)]
        price: u128,
    },
    #[command(name = "market.match_task", visible_alias = "market-match-task")]
    MarketMatchTask {
        #[arg(long)]
        task_id: u64,
    },
    #[command(name = "market.report", visible_alias = "market-report")]
    MarketReport {},
    DispatchOpen {
        #[arg(long, default_value = "worker-1")]
        worker_id: String,
        #[arg(long, default_value_t = DISPATCH_OPEN_LIMIT_DEFAULT)]
        limit: usize,
    },
    /// Run minimal RPC health server for service mode
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8545)]
        port: u16,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct AdapterRecord {
    ts: u64,
    kind: String,
    task_id: u64,
    worker: Option<String>,
    result_hash: Option<String>,
    status: String,
    #[serde(default)]
    tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MarketTask {
    task_id: u64,
    creator: String,
    bounty: u128,
    description: String,
    status: String,
    created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MarketBid {
    task_id: u64,
    worker: String,
    price: u128,
    created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct MarketReport {
    task_count: usize,
    open_task_count: usize,
    matched_task_count: usize,
    unmatched_task_count: usize,
    bid_count: usize,
    orphan_bid_count: usize,
    unique_bidder_count: usize,
    tasks_with_bids_count: usize,
    bid_coverage_rate: f64,
    avg_bids_per_task: f64,
    match_rate: f64,
    match_config: MarketScoreConfigOutput,
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
    result_hash: Option<String>,
    #[serde(default)]
    verifier_status: Option<String>,
    #[serde(default)]
    resolution_code: Option<String>,
    #[serde(default)]
    commit_tx_hash: Option<String>,
    #[serde(default)]
    reveal_tx_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct NodeEventRecord {
    event_type: String,
    task_id: u64,
    from_status: String,
    to_status: String,
    actor: String,
    tx_id: u64,
    block_height: u64,
    state_root: String,
    ts_unix_ms: u128,
    signer: Option<String>,
    challenger: Option<String>,
    tx_hash: Option<String>,
    resolution_code: Option<String>,
    treasury_delta: Option<i128>,
    challenger_delta: Option<i128>,
    bond_disposition: Option<String>,
    metering: Option<TaskMeteringQueryResponse>,
}

#[derive(Debug, Clone)]
struct QueryNormalizedAuditEventsQuery {
    source: Option<String>,
    event_type: Option<String>,
    cursor: Option<usize>,
    limit: usize,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedAuditEvent {
    source: String,
    event_type: String,
    actor: Option<String>,
    object_id: Option<String>,
    related_id: Option<String>,
    amount: Option<String>,
    reason: Option<String>,
    note: Option<String>,
    #[serde(rename = "checkedAt")]
    checked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct QueryNormalizedAuditEventsResponse {
    events: Vec<NormalizedAuditEvent>,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    #[serde(rename = "hasMore", skip_serializing_if = "Option::is_none")]
    has_more: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct ChallengeTreasuryEventView {
    event_type: String,
    task_id: u64,
    tx_id: u64,
    block_height: u64,
    ts_unix_ms: u128,
    challenger: Option<String>,
    bond_disposition: Option<String>,
    bond_amount: u128,
    escrow_delta: i128,
    forfeits_delta: u128,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OpsWindowArg {
    #[value(name = "24h")]
    H24,
    #[value(name = "7d")]
    D7,
    #[value(name = "custom")]
    Custom,
}

#[derive(Debug, Clone, Serialize)]
struct ChallengeDailySummary {
    posted: usize,
    refunded: usize,
    forfeited: usize,
    unresolved: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ChallengeWindowView {
    mode: String,
    from_unix_ms: u128,
    to_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct ChallengeTreasuryAnomaly {
    event_type: String,
    task_id: u64,
    tx_id: u64,
    code: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChallengeTreasuryQueryResponse {
    challenge_escrow_account: String,
    challenge_forfeits_account: String,
    current_escrow_balance: u128,
    current_forfeits_balance: u128,
    cumulative_forfeited: u128,
    events_total: usize,
    events: Vec<ChallengeTreasuryEventView>,
    anomaly_count: usize,
    anomalies: Vec<ChallengeTreasuryAnomaly>,
    daily_summary: Option<ChallengeDailySummary>,
    window: Option<ChallengeWindowView>,
    node_event_source_mode: String,
    node_event_log_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeEventScanMode {
    Authoritative,
    #[cfg(test)]
    RecentTail,
}

impl NodeEventScanMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            #[cfg(test)]
            Self::RecentTail => "recent_tail",
        }
    }
}

#[derive(Debug, Clone)]
struct LoadedNodeEvents {
    events: Vec<NodeEventRecord>,
    mode: NodeEventScanMode,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityAuditQueryResponse {
    token: CapabilityToken,
    owner_history: Vec<AuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CapabilityAuditQueryError {
    TokenNotFound(u64),
    InvalidRegistryState { field: &'static str, value: String },
}

impl CapabilityAuditQueryError {
    fn to_rpc_error(&self) -> RpcErrorResponse {
        match self {
            Self::TokenNotFound(token_id) => RpcErrorResponse {
                code: "CAPABILITY_NOT_FOUND",
                message: format!("capability token not found: {}", token_id),
            },
            Self::InvalidRegistryState { field, value } => RpcErrorResponse {
                code: "INVALID_REGISTRY_STATE",
                message: format!(
                    "non-canonical {} in identity registry snapshot: {}",
                    field, value
                ),
            },
        }
    }
}

fn load_latest_adapter_records() -> Vec<AdapterRecord> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = root.join("run/worker-agent");
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    let Some(latest) = files.last() else {
        return vec![];
    };

    let Ok(raw) = fs::read_to_string(latest) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AdapterRecord>(l).ok())
        .collect()
}

#[cfg(test)]
fn node_event_log_tail_bytes() -> u64 {
    std::env::var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(NODE_EVENT_LOG_TAIL_BYTES_MAX))
        .filter(|v| *v > 0)
        .unwrap_or(NODE_EVENT_LOG_TAIL_BYTES_DEFAULT)
}

#[cfg(test)]
fn read_log_tail(path: &Path, tail_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let start = size.saturating_sub(tail_bytes);
    let mut started_mid_line = false;
    if start > 0 {
        if file.seek(SeekFrom::Start(start.saturating_sub(1))).is_err() {
            return None;
        }
        let mut prev = [0u8; 1];
        if file.read_exact(&mut prev).is_err() {
            return None;
        }
        started_mid_line = prev[0] != b'\n';
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return None;
    }
    let buf = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 && started_mid_line {
        if let Some(idx) = buf.find('\n') {
            return Some(buf[idx + 1..].to_string());
        }
        return Some(String::new());
    }
    Some(buf)
}

fn trim_wrapped_log_numeric(raw: &str) -> &str {
    raw.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | ':' | '.' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
}

fn parse_u64_kv_value(raw: &str) -> Option<u64> {
    trim_wrapped_log_numeric(raw).parse::<u64>().ok()
}

fn parse_u128_kv_value(raw: &str) -> Option<u128> {
    trim_wrapped_log_numeric(raw).parse::<u128>().ok()
}

fn parse_i128_kv_value(raw: &str) -> Option<i128> {
    trim_wrapped_log_numeric(raw).parse::<i128>().ok()
}

fn normalize_opt_kv(kv: &BTreeMap<String, String>, key: &str) -> Option<String> {
    kv.get(key).and_then(|v| {
        let normalized = v.trim();
        let placeholder = normalized.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized == "-"
            || matches!(placeholder.as_str(), "null" | "none" | "n/a" | "na")
        {
            None
        } else {
            Some(normalized.to_string())
        }
    })
}

fn ceil_mul_div_u128(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    if value == 0 || numerator == 0 {
        return Some(0);
    }
    let product = value.checked_mul(numerator)?;
    let adjusted = product.checked_add(denominator.checked_sub(1)?)?;
    Some(adjusted / denominator)
}

fn parse_required_u64_kv_value(kv: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    kv.get(key)
        .and_then(|v| parse_u128_kv_value(v))
        .and_then(|v| u64::try_from(v).ok())
}

fn task_metering_derived_query_response(
    path: String,
    normalized_work_units: u128,
    policy: &TaskMeteringPolicyQueryResponse,
) -> TaskMeteringDerivedQueryResponse {
    let challenge_metered_bonus = ceil_mul_div_u128(
        normalized_work_units,
        policy.challenge_success_bounty_per_work_unit_num,
        policy.challenge_success_bounty_per_work_unit_den,
    )
    .unwrap_or(0);
    let worker_completion_bonus = ceil_mul_div_u128(
        normalized_work_units,
        policy.worker_completion_bonus_per_work_unit_num,
        policy.worker_completion_bonus_per_work_unit_den,
    )
    .unwrap_or(0);
    let worker_slash_rebate = ceil_mul_div_u128(
        normalized_work_units,
        policy.worker_slash_rebate_per_work_unit_num,
        policy.worker_slash_rebate_per_work_unit_den,
    )
    .unwrap_or(0);

    TaskMeteringDerivedQueryResponse {
        path,
        accept_floor_pass: normalized_work_units >= policy.min_accept_work_units,
        challenge_metered_bonus,
        challenge_bonus_total: policy
            .challenge_success_bounty_base
            .saturating_add(challenge_metered_bonus),
        worker_completion_bonus,
        worker_slash_rebate,
    }
}

fn metering_policy_has_nonzero_denominators(policy: &TaskMeteringPolicyQueryResponse) -> bool {
    policy.challenge_success_bounty_per_work_unit_den != 0
        && policy.worker_completion_bonus_per_work_unit_den != 0
        && policy.worker_slash_rebate_per_work_unit_den != 0
}

fn build_task_metering_query_response(
    path: String,
    workload_class: String,
    metering_schema: String,
    receipt_hash: String,
    prompt_tokens: u64,
    generated_tokens: u64,
    decode_steps: u64,
    kv_bytes_moved: u64,
    normalized_work_units: u128,
    prompt_token_weight: u128,
    generated_token_weight: u128,
    decode_step_weight: u128,
    kv_byte_weight: u128,
    policy: TaskMeteringPolicyQueryResponse,
) -> TaskMeteringQueryResponse {
    let derived = task_metering_derived_query_response(path, normalized_work_units, &policy);
    TaskMeteringQueryResponse {
        workload_class,
        metering_schema,
        receipt_hash,
        prompt_tokens,
        generated_tokens,
        decode_steps,
        kv_bytes_moved,
        normalized_work_units,
        prompt_token_weight,
        generated_token_weight,
        decode_step_weight,
        kv_byte_weight,
        policy,
        derived,
    }
}

fn parse_event_metering_query_response(
    kv: &BTreeMap<String, String>,
) -> Option<TaskMeteringQueryResponse> {
    let workload_class = normalize_opt_kv(kv, "metering_workload_class")?;
    let metering_schema = normalize_opt_kv(kv, "metering_schema")?;
    let receipt_hash = normalize_opt_kv(kv, "metering_receipt_hash")?;
    let policy_snapshot_version = kv
        .get("metering_policy_snapshot_version")
        .and_then(|v| parse_u128_kv_value(v))
        .and_then(|v| u8::try_from(v).ok())?;

    let metering_path = normalize_opt_kv(kv, "to_status")?;
    let normalized_work_units = kv
        .get("metering_normalized_work_units")
        .and_then(|v| parse_u128_kv_value(v))?;
    let policy = TaskMeteringPolicyQueryResponse {
        snapshot_version: policy_snapshot_version,
        min_accept_work_units: kv
            .get("metering_min_accept_work_units")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_base: kv
            .get("metering_challenge_success_bounty_base")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_per_work_unit_num: kv
            .get("metering_challenge_success_bounty_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        challenge_success_bounty_per_work_unit_den: kv
            .get("metering_challenge_success_bounty_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_completion_bonus_per_work_unit_num: kv
            .get("metering_worker_completion_bonus_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_completion_bonus_per_work_unit_den: kv
            .get("metering_worker_completion_bonus_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_slash_rebate_per_work_unit_num: kv
            .get("metering_worker_slash_rebate_per_work_unit_num")
            .and_then(|v| parse_u128_kv_value(v))?,
        worker_slash_rebate_per_work_unit_den: kv
            .get("metering_worker_slash_rebate_per_work_unit_den")
            .and_then(|v| parse_u128_kv_value(v))?,
    };
    if !metering_policy_has_nonzero_denominators(&policy) {
        return None;
    }

    Some(build_task_metering_query_response(
        metering_path,
        workload_class,
        metering_schema,
        receipt_hash,
        parse_required_u64_kv_value(kv, "metering_prompt_tokens")?,
        parse_required_u64_kv_value(kv, "metering_generated_tokens")?,
        parse_required_u64_kv_value(kv, "metering_decode_steps")?,
        parse_required_u64_kv_value(kv, "metering_kv_bytes_moved")?,
        normalized_work_units,
        kv.get("metering_prompt_token_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_generated_token_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_decode_step_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        kv.get("metering_kv_byte_weight")
            .and_then(|v| parse_u128_kv_value(v))?,
        policy,
    ))
}

fn parse_event_log_kv(line: &str) -> BTreeMap<String, String> {
    let mut kv = BTreeMap::<String, String>::new();
    let mut i = 0usize;
    let bytes = line.as_bytes();
    let len = bytes.len();

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }

        let key_start = i;
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= len || bytes[i] != b'=' {
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let key_end = i;
        i += 1;

        if key_end <= key_start {
            continue;
        }
        let key = &line[key_start..key_end];

        let value = if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let quote = bytes[i];
            i += 1;
            let mut out = String::new();
            while i < len {
                let b = bytes[i];
                i += 1;
                if b == quote {
                    break;
                }
                if b == b'\\' && i < len {
                    out.push(bytes[i] as char);
                    i += 1;
                } else {
                    out.push(b as char);
                }
            }
            out
        } else {
            let val_start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            line[val_start..i].to_string()
        };

        kv.insert(key.to_string(), value);
    }

    kv
}

fn parse_node_event_log_sources_list(raw: &str) -> Vec<PathBuf> {
    raw.split(|c: char| c == ',' || c == ';' || c == '\n')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .collect()
}

fn discover_default_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let run_dir = root.join("run");
    let mut out = BTreeSet::<PathBuf>::new();
    for seed in ["event-field-check.log", "parallel-sanity.log"] {
        let candidate = run_dir.join(seed);
        if candidate.is_file() {
            out.insert(candidate);
        }
    }
    if let Ok(entries) = fs::read_dir(&run_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if name.ends_with(".log") {
                out.insert(path);
            }
        }
    }
    out.into_iter().collect()
}

fn load_node_event_log_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = BTreeSet::<PathBuf>::new();

    if let Some(manifest_path) = normalized_path_from_env(NODE_EVENT_LOG_MANIFEST_ENV) {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let path = PathBuf::from(trimmed);
                let resolved = if path.is_absolute() {
                    path
                } else {
                    manifest_dir.join(path)
                };
                sources.insert(resolved);
            }
        }
    }

    if let Ok(raw) = std::env::var(NODE_EVENT_LOG_SOURCES_ENV) {
        for path in parse_node_event_log_sources_list(&raw) {
            let resolved = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            sources.insert(resolved);
        }
    }

    if sources.is_empty() {
        return discover_default_node_event_log_sources(root);
    }

    sources.into_iter().collect()
}

fn node_event_log_candidates(root: &Path) -> Vec<PathBuf> {
    load_node_event_log_sources(root)
}

fn load_node_events_from_root(root: &Path, mode: NodeEventScanMode) -> LoadedNodeEvents {
    let candidates = node_event_log_candidates(root);
    #[cfg(test)]
    let tail_bytes = node_event_log_tail_bytes();
    let mut lines = Vec::new();
    #[cfg(test)]
    let mut truncated = false;
    #[cfg(not(test))]
    let truncated = false;
    for p in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&p).ok(),
            #[cfg(test)]
            NodeEventScanMode::RecentTail => {
                if let Ok(meta) = fs::metadata(&p) {
                    if meta.len() > tail_bytes {
                        truncated = true;
                    }
                }
                read_log_tail(&p, tail_bytes)
            }
        };
        if let Some(raw) = raw {
            lines.extend(raw.lines().map(str::to_string));
        }
    }

    let mut out = Vec::new();
    for line in lines {
        let Some(event_pos) = line.find("[event]") else {
            continue;
        };
        let event_line = &line[event_pos..];
        if !event_line.contains("event_type=") {
            continue;
        }
        let kv = parse_event_log_kv(event_line);

        let Some(task_id) = kv.get("task_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(tx_id) = kv.get("tx_id").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let Some(block_height) = kv.get("block_height").and_then(|s| parse_u64_kv_value(s)) else {
            continue;
        };
        let ts_unix_ms = kv
            .get("ts_unix_ms")
            .and_then(|s| parse_u128_kv_value(s))
            .unwrap_or(0);

        let normalize_opt = |k: &str| normalize_opt_kv(&kv, k);

        out.push(NodeEventRecord {
            event_type: kv
                .get("event_type")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            task_id,
            from_status: kv
                .get("from_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            to_status: kv
                .get("to_status")
                .cloned()
                .unwrap_or_else(|| "NONE".into()),
            actor: kv.get("actor").cloned().unwrap_or_else(|| "unknown".into()),
            tx_id,
            block_height,
            state_root: kv
                .get("state_root")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            ts_unix_ms,
            signer: normalize_opt("signer"),
            challenger: normalize_opt("challenger"),
            tx_hash: normalize_opt("tx_hash"),
            resolution_code: normalize_opt("resolution_code"),
            treasury_delta: kv
                .get("treasury_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            challenger_delta: kv
                .get("challenger_delta")
                .and_then(|v| parse_i128_kv_value(v)),
            bond_disposition: normalize_opt("bond_disposition"),
            metering: parse_event_metering_query_response(&kv),
        });
    }
    LoadedNodeEvents {
        events: out,
        mode,
        truncated,
    }
}

fn load_node_events(mode: NodeEventScanMode) -> LoadedNodeEvents {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    load_node_events_from_root(&root, mode)
}

#[cfg(test)]
fn load_latest_node_events() -> Vec<NodeEventRecord> {
    load_node_events(NodeEventScanMode::RecentTail).events
}

fn governance_state() -> StateStore {
    let mut st = StateStore::new();
    let _ = st.put_proposal_new(GovProposalObject {
        proposal_id: 9001,
        title: "update max_block_ms".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Voting,
        version: 1,
    });
    let _ = st.set_gov_param(0, 7001, "max_block_ms".into(), "10".into());
    let _ = st.set_gov_param(
        0,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "false".into(),
    );
    st
}

fn run_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn now_ms() -> u128 {
    if let Ok(v) = std::env::var("TRNM_RPC_NOW_MS") {
        if let Ok(parsed) = v.parse::<u128>() {
            return parsed;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn identity_registry_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_IDENTITY_REGISTRY_FILE") {
        return path;
    }
    run_root().join("run/rpc/identity_registry.json")
}

fn load_identity_registry(path: &Path) -> IdentityRegistry {
    let Ok(raw) = fs::read_to_string(path) else {
        return IdentityRegistry::default();
    };
    serde_json::from_str::<IdentityRegistry>(&raw).unwrap_or_default()
}

fn query_capability_audit(
    registry: &IdentityRegistry,
    token_id: u64,
) -> Result<CapabilityAuditQueryResponse, CapabilityAuditQueryError> {
    let Some(token) = registry.capability(token_id).cloned() else {
        return Err(CapabilityAuditQueryError::TokenNotFound(token_id));
    };

    if !IdentityRegistry::is_canonical_did(&token.subject_did) {
        return Err(CapabilityAuditQueryError::InvalidRegistryState {
            field: "subject_did",
            value: token.subject_did.clone(),
        });
    }

    let mut owner_history: Vec<_> = registry
        .audit_trail()
        .iter()
        .filter(|event| event.subject == token.subject_did)
        .cloned()
        .collect();

    if let Some(invalid_subject) = owner_history
        .iter()
        .map(|event| event.subject.as_str())
        .find(|subject| !IdentityRegistry::is_canonical_did(subject))
    {
        return Err(CapabilityAuditQueryError::InvalidRegistryState {
            field: "owner_history.subject",
            value: invalid_subject.to_string(),
        });
    }

    // Keep audit query output deterministic even when registry snapshots are
    // merged/imported with non-canonical ordering.
    owner_history.sort_by_key(|event| (event.at_height, event.seq));

    Ok(CapabilityAuditQueryResponse {
        token,
        owner_history,
    })
}

fn env_u64_with_min(name: &str, default: u64, min: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            let normalized = normalize_wrapped_env_value(&v);
            if normalized.is_empty() {
                None
            } else {
                normalized.parse::<u64>().ok()
            }
        })
        .map(|v| v.max(min))
        .unwrap_or(default.max(min))
}

fn env_u32_with_min(name: &str, default: u32, min: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            let normalized = normalize_wrapped_env_value(&v);
            if normalized.is_empty() {
                None
            } else {
                normalized.parse::<u32>().ok()
            }
        })
        .map(|v| v.max(min))
        .unwrap_or(default.max(min))
}

fn make_request_id(
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
    ts: u128,
) -> String {
    let mut h = Sha256::new();
    h.update(channel.as_bytes());
    h.update(b"|");
    h.update(user_id.as_bytes());
    h.update(b"|");
    h.update(session_id.as_bytes());
    h.update(b"|");
    h.update(idempotency_key.as_bytes());
    h.update(b"|");
    h.update(ts.to_string().as_bytes());
    let digest = hex::encode(h.finalize());
    format!("req_{}", &digest[..16])
}

fn ingress_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_INGRESS_FILE") {
        return path;
    }
    run_root().join("run/message-gateway/requests.jsonl")
}

fn submit_message_max_bytes() -> u64 {
    env_u64_with_min(
        SUBMIT_MESSAGE_MAX_BYTES_ENV,
        SUBMIT_MESSAGE_MAX_BYTES_DEFAULT,
        SUBMIT_MESSAGE_MAX_BYTES_MIN,
    )
}

fn normalize_wrapped_env_value(raw: &str) -> &str {
    let mut normalized = raw.trim();
    while normalized.len() >= 2 {
        let wrapped_by_quotes = (normalized.starts_with('"') && normalized.ends_with('"'))
            || (normalized.starts_with('\'') && normalized.ends_with('\''))
            || (normalized.starts_with('`') && normalized.ends_with('`'));
        if !wrapped_by_quotes {
            break;
        }
        normalized = normalized[1..normalized.len() - 1].trim();
    }
    normalized
}

fn normalized_path_from_env(name: &str) -> Option<PathBuf> {
    let raw = std::env::var(name).ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        None
    } else {
        Some(PathBuf::from(normalized))
    }
}

fn market_tasks_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE") {
        return path;
    }
    run_root().join("run/market/tasks.jsonl")
}

fn market_bids_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_MARKET_BIDS_FILE") {
        return path;
    }
    run_root().join("run/market/bids.jsonl")
}

fn task_state_file() -> Option<PathBuf> {
    normalized_path_from_env(TASK_STATE_FILE_ENV)
}

fn load_task_state_snapshot() -> Result<Vec<TaskObject>> {
    let Some(path) = task_state_file() else {
        return Ok(vec![]);
    };
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(err) => {
            return Err(anyhow!(
                "failed to read task state snapshot {}: {}",
                path.display(),
                err
            ))
        }
    };

    let mut tasks = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let task = serde_json::from_str::<TaskObject>(line).map_err(|err| {
            anyhow!(
                "failed to parse task state snapshot {} line {}: {}",
                path.display(),
                idx + 1,
                err
            )
        })?;
        tasks.push(task);
    }
    Ok(tasks)
}

fn task_status_path(status: TaskStatus) -> String {
    match status {
        TaskStatus::Open => "Open",
        TaskStatus::Assigned => "Assigned",
        TaskStatus::Committed => "Committed",
        TaskStatus::Revealed => "Revealed",
        TaskStatus::Challenged => "Challenged",
        TaskStatus::Completed => "Completed",
        TaskStatus::Slashed => "Slashed",
    }
    .to_string()
}

fn task_metering_query_response(
    snapshot: &TaskMeteringSnapshot,
    path: String,
) -> Option<TaskMeteringQueryResponse> {
    let policy = TaskMeteringPolicyQueryResponse {
        snapshot_version: snapshot.policy_snapshot_version,
        min_accept_work_units: snapshot.min_accept_work_units,
        challenge_success_bounty_base: snapshot.challenge_success_bounty_base,
        challenge_success_bounty_per_work_unit_num: snapshot
            .challenge_success_bounty_per_work_unit_num,
        challenge_success_bounty_per_work_unit_den: snapshot
            .challenge_success_bounty_per_work_unit_den,
        worker_completion_bonus_per_work_unit_num: snapshot
            .worker_completion_bonus_per_work_unit_num,
        worker_completion_bonus_per_work_unit_den: snapshot
            .worker_completion_bonus_per_work_unit_den,
        worker_slash_rebate_per_work_unit_num: snapshot.worker_slash_rebate_per_work_unit_num,
        worker_slash_rebate_per_work_unit_den: snapshot.worker_slash_rebate_per_work_unit_den,
    };
    if policy.snapshot_version == 0
        || policy.challenge_success_bounty_per_work_unit_den == 0
        || policy.worker_completion_bonus_per_work_unit_den == 0
        || policy.worker_slash_rebate_per_work_unit_den == 0
    {
        return None;
    }
    Some(build_task_metering_query_response(
        path,
        snapshot.workload_class.clone(),
        snapshot.metering_schema.clone(),
        snapshot.receipt_hash.clone(),
        snapshot.prompt_tokens,
        snapshot.generated_tokens,
        snapshot.decode_steps,
        snapshot.kv_bytes_moved,
        snapshot.normalized_work_units,
        snapshot.prompt_token_weight,
        snapshot.generated_token_weight,
        snapshot.decode_step_weight,
        snapshot.kv_byte_weight,
        policy,
    ))
}

fn query_task_from_state_snapshot(task_id: u64, tasks: &[TaskObject]) -> Option<TaskQueryResponse> {
    let task = tasks
        .iter()
        .filter(|task| task.task_id == task_id)
        .max_by_key(|task| task.version)?;
    let metadata_report = task
        .metadata
        .as_ref()
        .map(|metadata| metadata.compatibility_report());

    Some(TaskQueryResponse {
        task_id: task.task_id,
        status: task.status,
        worker: task.worker.clone(),
        bounty: task.bounty,
        result_hash_hex: task.result_hash.map(hex::encode),
        version: task.version,
        metadata_compatibility: metadata_report.as_ref().map(|report| report.compatibility),
        metadata_runtime_compatible: metadata_report
            .as_ref()
            .map(|report| report.compatibility.is_runtime_compatible()),
        metadata_requires_governance_upgrade: metadata_report
            .as_ref()
            .map(|report| report.requires_governance_upgrade),
        metadata_primary_compatibility_finding: metadata_report
            .as_ref()
            .and_then(|report| report.primary_finding()),
        metadata_compatibility_findings: metadata_report
            .as_ref()
            .and_then(|report| report.findings_nonempty()),
        metering: task
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.metering.as_ref())
            .and_then(|snapshot| {
                task_metering_query_response(snapshot, task_status_path(task.status))
            }),
    })
}

struct MarketFileLock {
    lock_path: PathBuf,
}

impl Drop for MarketFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn market_lock_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("market-data");
    path.with_file_name(format!("{}.lock", file_name))
}

fn market_lock_stale_after_ms() -> Option<u128> {
    let raw = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok()?;
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return None;
    }
    let parsed = normalized.parse::<u128>().ok()?;
    Some(parsed.clamp(1_000, 15 * 60 * 1_000))
}

fn market_lock_timeout_ms() -> u64 {
    let raw = match std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    let normalized = normalize_wrapped_env_value(&raw);
    if normalized.is_empty() {
        return MARKET_LOCK_TIMEOUT_MS_DEFAULT;
    }
    let parsed = match normalized.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return MARKET_LOCK_TIMEOUT_MS_DEFAULT,
    };
    parsed.clamp(MARKET_LOCK_TIMEOUT_MS_MIN, MARKET_LOCK_TIMEOUT_MS_MAX)
}

fn acquire_market_file_lock(path: &Path) -> Result<MarketFileLock> {
    let lock_path = market_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let stale_after_ms = market_lock_stale_after_ms();
    let timeout = Duration::from_millis(market_lock_timeout_ms());
    let start = Instant::now();
    loop {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                return Ok(MarketFileLock { lock_path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(stale_after_ms) = stale_after_ms {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                                if elapsed.as_millis() > stale_after_ms {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                    }
                }
                if start.elapsed() >= timeout {
                    return Err(anyhow!(
                        "timed out waiting for market file lock after {}ms: {}",
                        timeout.as_millis(),
                        lock_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                return Err(anyhow!(
                    "failed to acquire market file lock {}: {}",
                    lock_path.display(),
                    err
                ));
            }
        }
    }
}

fn write_string_atomically(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("market"),
        std::process::id(),
        ts
    ));

    fs::write(&tmp, content)?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn load_market_tasks() -> Vec<MarketTask> {
    let path = market_tasks_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketTask>(l).ok())
        .collect()
}

fn save_market_tasks(tasks: &[MarketTask]) -> Result<()> {
    let path = market_tasks_file();
    let mut out = String::new();
    for t in tasks {
        out.push_str(&serde_json::to_string(t)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

fn load_market_bids() -> Vec<MarketBid> {
    let path = market_bids_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MarketBid>(l).ok())
        .collect()
}

fn save_market_bids(bids: &[MarketBid]) -> Result<()> {
    let path = market_bids_file();
    let mut out = String::new();
    for b in bids {
        out.push_str(&serde_json::to_string(b)?);
        out.push('\n');
    }
    write_string_atomically(&path, &out)
}

fn market_reputation_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env(MARKET_REPUTATION_FILE_ENV) {
        return path;
    }
    run_root().join("run/market/reputation.json")
}

fn normalize_market_worker_key(raw: &str) -> Option<String> {
    let sanitized = raw
        .trim()
        .chars()
        // M2 micro-hardening: strip invisible joiner/ZWSP/word-joiner/BOM
        // and soft-hyphen code points so alias normalization cannot be bypassed
        // by hidden chars while preserving visible delimiters like '-' used by
        // existing worker IDs.
        .filter_map(|ch| match ch {
            // Treat invisible separators as whitespace so aliases like
            // "worker\u200ba" and "worker\u2060b" collapse to canonical keys.
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            // Strip soft-hyphen entirely to avoid creating fake separators.
            '\u{00AD}' => None,
            // Treat control bytes as whitespace separators so malformed/injected
            // worker IDs cannot avoid alias-collapse by embedding ASCII controls.
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>();
    let normalized = sanitized
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn market_worker_tie_break_key(raw: &str) -> String {
    normalize_market_worker_key(raw).unwrap_or_else(|| raw.trim().to_ascii_lowercase())
}

fn normalize_market_status_key(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter_map(|ch| match ch {
            // Treat invisible/control separators as whitespace so status checks
            // remain stable against malformed JSONL producers and hidden-char drift.
            '\u{00AD}' => None,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect::<String>()
        .to_ascii_lowercase()
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_actor_or_signer(raw: &str) -> Option<String> {
    let sanitized: String = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => Some(' '),
            _ if ch.is_whitespace() || ch.is_control() => Some(' '),
            _ => Some(ch),
        })
        .collect();
    let collapsed = sanitized
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

fn parse_market_reputation_value(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| {
            let float = value.as_f64()?;
            if !float.is_finite() || float.fract() != 0.0 {
                return None;
            }
            if float < i64::MIN as f64 || float > i64::MAX as f64 {
                return None;
            }
            Some(float as i64)
        })
        .or_else(|| value.as_str()?.trim().parse::<i64>().ok())
}

fn stronger_market_reputation_signal(existing: i64, candidate: i64) -> i64 {
    let existing_abs = existing.unsigned_abs();
    let candidate_abs = candidate.unsigned_abs();
    match candidate_abs.cmp(&existing_abs) {
        std::cmp::Ordering::Greater => candidate,
        std::cmp::Ordering::Less => existing,
        std::cmp::Ordering::Equal => {
            if candidate < existing {
                candidate
            } else {
                existing
            }
        }
    }
}

fn load_market_reputation() -> BTreeMap<String, i64> {
    let path = market_reputation_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    // M2 resilience: tolerate partially malformed fixtures by salvaging any
    // object entries that still deserialize into i64 reputation values.
    let parsed = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    let mut normalized: BTreeMap<String, i64> = BTreeMap::new();
    for (worker, rep_value) in parsed {
        let Some(rep) = parse_market_reputation_value(&rep_value) else {
            continue;
        };
        if let Some(key) = normalize_market_worker_key(&worker) {
            normalized
                .entry(key)
                // M2 hardening: if aliases normalize to the same worker key,
                // keep the strongest absolute reputation signal; on equal
                // magnitude prefer the more negative value to stay fail-closed.
                .and_modify(|existing| {
                    *existing = stronger_market_reputation_signal(*existing, rep)
                })
                .or_insert(rep);
        }
    }
    normalized
}

fn env_u128_clamped(name: &str, default: u128, min: u128, max: u128) -> u128 {
    std::env::var(name)
        .ok()
        .and_then(|v| normalize_wrapped_env_value(&v).parse::<u128>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_i64_clamped(name: &str, default: i64, min: i64, max: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| normalize_wrapped_env_value(&v).parse::<i64>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

#[derive(Debug, Clone, Copy)]
struct MarketScoreConfig {
    price_weight: u128,
    reputation_weight: u128,
    reputation_clamp: i64,
}

#[derive(Debug, Clone, Serialize)]
struct MarketScoreConfigOutput {
    price_weight: u128,
    reputation_weight: u128,
    reputation_clamp: i64,
    max_reputation_score_delta: u128,
    min_reputation_score_delta: i128,
}

#[derive(Debug, Clone, Copy)]
struct MarketScoreBreakdown {
    effective_reputation: i64,
    base_score: u128,
    reputation_reward: u128,
    penalty: u128,
    effective_score: u128,
    score_floor_applied: bool,
}

impl From<MarketScoreConfig> for MarketScoreConfigOutput {
    fn from(value: MarketScoreConfig) -> Self {
        let reputation_clamp = normalized_reputation_clamp(value.reputation_clamp);
        let max_reputation_score_delta =
            (reputation_clamp as u128).saturating_mul(value.reputation_weight);
        Self {
            price_weight: value.price_weight,
            reputation_weight: value.reputation_weight,
            reputation_clamp,
            max_reputation_score_delta,
            min_reputation_score_delta: -(max_reputation_score_delta.min(i128::MAX as u128)
                as i128),
        }
    }
}

fn market_score_config() -> MarketScoreConfig {
    MarketScoreConfig {
        price_weight: env_u128_clamped(
            MARKET_PRICE_WEIGHT_ENV,
            MARKET_PRICE_WEIGHT_DEFAULT,
            MARKET_WEIGHT_MIN,
            MARKET_WEIGHT_MAX,
        ),
        reputation_weight: env_u128_clamped(
            MARKET_REPUTATION_WEIGHT_ENV,
            MARKET_REPUTATION_WEIGHT_DEFAULT,
            MARKET_WEIGHT_MIN,
            MARKET_WEIGHT_MAX,
        ),
        reputation_clamp: env_i64_clamped(
            MARKET_REPUTATION_CLAMP_ENV,
            MARKET_REPUTATION_CLAMP_DEFAULT,
            MARKET_REPUTATION_CLAMP_MIN,
            MARKET_REPUTATION_CLAMP_MAX,
        ),
    }
}

fn normalized_reputation_clamp(clamp: i64) -> i64 {
    clamp.max(MARKET_REPUTATION_CLAMP_MIN)
}

fn clamp_reputation_for_market(reputation: i64, cfg: MarketScoreConfig) -> i64 {
    let clamp = normalized_reputation_clamp(cfg.reputation_clamp);
    reputation.clamp(-clamp, clamp)
}

fn market_reputation_score_delta(breakdown: &MarketScoreBreakdown) -> i128 {
    if breakdown.effective_reputation >= 0 {
        -(breakdown.reputation_reward.min(i128::MAX as u128) as i128)
    } else {
        breakdown.penalty.min(i128::MAX as u128) as i128
    }
}

fn market_score_breakdown(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> MarketScoreBreakdown {
    let effective_reputation = clamp_reputation_for_market(reputation, cfg);
    let base_score = price.saturating_mul(cfg.price_weight);
    if effective_reputation >= 0 {
        let reputation_reward =
            (effective_reputation as u128).saturating_mul(cfg.reputation_weight);
        let score_floor_applied = reputation_reward > base_score;
        MarketScoreBreakdown {
            effective_reputation,
            base_score,
            reputation_reward,
            penalty: 0,
            effective_score: base_score.saturating_sub(reputation_reward),
            score_floor_applied,
        }
    } else {
        let penalty =
            (effective_reputation.unsigned_abs() as u128).saturating_mul(cfg.reputation_weight);
        MarketScoreBreakdown {
            effective_reputation,
            base_score,
            reputation_reward: 0,
            penalty,
            effective_score: base_score.saturating_add(penalty),
            score_floor_applied: false,
        }
    }
}

fn market_effective_score_with_config(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> u128 {
    market_score_breakdown(price, reputation, cfg).effective_score
}

#[cfg(test)]
fn market_effective_score(price: u128, reputation: i64) -> u128 {
    market_effective_score_with_config(price, reputation, market_score_config())
}

fn atomic_write_text_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}-{}",
        file_name,
        std::process::id(),
        now_ms()
    ));

    {
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    fs::rename(&tmp, path)?;

    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IngressQuarantineRecord {
    source_path: String,
    line_number: usize,
    line_hash: u64,
    raw_line: String,
    error: String,
    quarantined_at_unix_ms: u128,
}

fn ingress_quarantine_file_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("requests.jsonl");
    path.with_file_name(format!("{}.quarantine.jsonl", file_name))
}

fn stable_line_hash(raw: &str) -> u64 {
    // Keep this deterministic across process restarts and toolchain/runtime changes
    // so quarantine dedupe remains stable for identical bad ingress rows.
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn canonical_quarantine_source_path(path: &str) -> String {
    path.trim().to_string()
}

fn quarantine_fingerprint(entry: &IngressQuarantineRecord) -> (String, u64) {
    (
        canonical_quarantine_source_path(&entry.source_path),
        entry.line_hash,
    )
}

fn parse_quarantine_fingerprint_line(line: &str) -> Option<(String, u64)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let value = serde_json::from_str::<serde_json::Value>(trimmed).ok()?;
    let line_hash = value
        .get("line_hash")
        .and_then(|hash| hash.as_u64())
        .or_else(|| {
            value
                .get("raw_line")
                .and_then(|raw| raw.as_str())
                .map(|raw| stable_line_hash(raw.trim()))
        })?;
    Some((
        canonical_quarantine_source_path(value.get("source_path")?.as_str()?),
        line_hash,
    ))
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<usize> {
    const INGRESS_QUARANTINE_FILE_MAX_RECORDS: usize = 256;
    const INGRESS_QUARANTINE_READ_MAX_BYTES: u64 = 1_048_576;
    const INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES: usize = 16_384;

    if entries.is_empty() {
        return Ok(0);
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut existing: Vec<serde_json::Value> = Vec::new();
    let mut existing_keys: Vec<(String, u64)> = Vec::new();

    if let Ok(raw) = fs::read_to_string(&quarantine_path) {
        if (raw.len() as u64) <= INGRESS_QUARANTINE_READ_MAX_BYTES {
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let Some(key) = parse_quarantine_fingerprint_line(trimmed) else {
                    continue;
                };

                let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };

                if let Some(pos) = existing_keys.iter().position(|(entry_source, entry_hash)| {
                    entry_source == &key.0 && entry_hash == &key.1
                }) {
                    existing.remove(pos);
                    existing_keys.remove(pos);
                }

                existing.push(value);
                existing_keys.push(key);
            }
        }
    }

    let mut seen_batch = std::collections::HashSet::new();
    let mut appended = 0usize;
    for entry in entries {
        let key = quarantine_fingerprint(entry);
        if !seen_batch.insert(key.clone()) {
            continue;
        }

        if existing_keys
            .iter()
            .any(|(entry_source, entry_hash)| entry_source == &key.0 && entry_hash == &key.1)
        {
            continue;
        }

        appended += 1;

        let mut value = serde_json::to_value(entry)?;
        if let Some(serde_json::Value::String(raw_line)) = value.get_mut("raw_line") {
            let mut sanitized = raw_line.clone();
            if sanitized.len() > INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES {
                let mut end = INGRESS_QUARANTINE_RETAINED_LINE_MAX_BYTES;
                while end > 0 && !sanitized.is_char_boundary(end) {
                    end -= 1;
                }
                sanitized.truncate(end);
                *raw_line = sanitized;
            }
        }

        existing.push(value);
        existing_keys.push(key);
    }

    if existing.len() > INGRESS_QUARANTINE_FILE_MAX_RECORDS {
        let drop_count = existing.len() - INGRESS_QUARANTINE_FILE_MAX_RECORDS;
        existing.drain(0..drop_count);
        existing_keys.drain(0..drop_count);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&quarantine_path)?;
    for entry in existing {
        writeln!(file, "{}", entry.to_string())?;
    }
    file.sync_all()?;

    Ok(appended)
}

fn load_ingress_records() -> Vec<MessageIngressRecord> {
    const INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES: usize = 4096;

    fn truncate_for_quarantine(raw: &str) -> String {
        if raw.len() <= INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES {
            return raw.to_string();
        }
        let mut end = INGRESS_QUARANTINE_RAW_LINE_MAX_BYTES;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        raw[..end].to_string()
    }

    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let source_path = path.display().to_string();
    let mut seen_quarantine_keys: std::collections::HashSet<(String, u64)> =
        std::collections::HashSet::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<MessageIngressRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(err) => {
                let line_hash = stable_line_hash(trimmed);
                let key = (source_path.clone(), line_hash);
                if seen_quarantine_keys.insert(key) {
                    quarantined.push(IngressQuarantineRecord {
                        source_path: source_path.clone(),
                        line_number: idx + 1,
                        line_hash,
                        raw_line: truncate_for_quarantine(line),
                        error: err.to_string(),
                        quarantined_at_unix_ms: now_ms(),
                    });
                }
            }
        }
    }
    if !quarantined.is_empty() {
        match append_quarantine_records(&path, &quarantined) {
            Err(err) => {
                eprintln!(
                    "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined={} err={}",
                    path.display(),
                    quarantined.len(),
                    err
                );
            }
            Ok(appended) if appended > 0 => {
                eprintln!(
                    "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined={} quarantine_path={}",
                    path.display(),
                    appended,
                    ingress_quarantine_file_for(&path).display()
                );
            }
            Ok(_) => {}
        }
    }
    records
}

fn save_ingress_records(records: &[MessageIngressRecord]) -> Result<()> {
    let path = ingress_file();
    let mut out = String::new();
    for rec in records {
        out.push_str(&serde_json::to_string(rec)?);
        out.push('\n');
    }
    atomic_write_text_file(&path, &out)
}

fn next_ingress_task_id(records: &[MessageIngressRecord]) -> Result<u64> {
    let max_existing = records.iter().map(|r| r.task_id).max().unwrap_or(10_000);
    max_existing
        .checked_add(1)
        .ok_or_else(|| anyhow!("ingress task_id exhausted: {}", max_existing))
}

fn is_same_submit_message_idempotency_scope(
    rec: &MessageIngressRecord,
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
) -> bool {
    rec.idempotency_key == idempotency_key
        && rec.session_id == session_id
        && rec.channel == channel
        && rec.user_id == user_id
}

fn is_lower_hex_64(input: &str) -> bool {
    input.len() == 64
        && input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_nonempty_no_whitespace(input: &str) -> bool {
    !input.is_empty() && !input.chars().any(|c| c.is_whitespace())
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

fn is_canonical_rfc3339_utc_z(input: &str) -> bool {
    if input.len() != 20 {
        return false;
    }
    let bytes = input.as_bytes();
    if !(bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit()))
    {
        return false;
    }

    let parse_u32 =
        |start: usize, end: usize| -> Option<u32> { input.get(start..end)?.parse().ok() };

    let Some(year) = parse_u32(0, 4) else {
        return false;
    };
    let Some(month) = parse_u32(5, 7) else {
        return false;
    };
    let Some(day) = parse_u32(8, 10) else {
        return false;
    };
    let Some(hour) = parse_u32(11, 13) else {
        return false;
    };
    let Some(minute) = parse_u32(14, 16) else {
        return false;
    };
    let Some(second) = parse_u32(17, 19) else {
        return false;
    };

    let Some(max_day) = days_in_month(year, month) else {
        return false;
    };

    (1..=max_day).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn validate_task_metadata_core_fields(metadata: &TaskMetadata) -> Result<()> {
    if let Some(task_type) = metadata.task_type.as_deref() {
        if !is_nonempty_no_whitespace(task_type) {
            bail!("metadata.task_type must be non-empty and whitespace-free");
        }
    }

    if let Some(input_hash) = metadata.input_hash.as_deref() {
        if !is_lower_hex_64(input_hash) {
            bail!("metadata.input_hash must be 64-char lowercase hex");
        }
    }

    if let Some(model) = metadata.model.as_ref() {
        if let Some(model_id) = model.model_id.as_deref() {
            if !is_nonempty_no_whitespace(model_id) {
                bail!("metadata.model.model_id must be non-empty and whitespace-free");
            }
        }
        if let Some(model_digest) = model.model_digest.as_deref() {
            if !is_lower_hex_64(model_digest) {
                bail!("metadata.model.model_digest must be 64-char lowercase hex");
            }
        }
        if let Some(version) = model.version.as_deref() {
            if !is_nonempty_no_whitespace(version) {
                bail!("metadata.model.version must be non-empty and whitespace-free");
            }
        }
    }

    if let Some(provenance) = metadata.provenance.as_ref() {
        if let Some(producer_did) = provenance.producer_did.as_deref() {
            if !(producer_did.starts_with("did:") && is_nonempty_no_whitespace(producer_did)) {
                bail!("metadata.provenance.producer_did must be canonical did:* token");
            }
        }

        if let Some(produced_at) = provenance.produced_at.as_deref() {
            if !is_canonical_rfc3339_utc_z(produced_at) {
                bail!("metadata.provenance.produced_at must be canonical RFC3339 UTC Z timestamp");
            }
        }

        if let Some(provenance_index) = provenance.provenance_index.as_deref() {
            if !provenance_index.starts_with("prov:")
                || provenance_index.len() < 13
                || !is_nonempty_no_whitespace(provenance_index)
            {
                bail!("metadata.provenance.provenance_index must use prov:* canonical form");
            }
        }

        match provenance.privacy_tier {
            Some(PrivacyTier::Public) => {
                if provenance.provenance_index.is_some() {
                    bail!(
                        "metadata.provenance.provenance_index must be absent when privacy_tier=public"
                    );
                }
            }
            Some(PrivacyTier::Internal) | Some(PrivacyTier::Restricted) => {
                if provenance.provenance_index.is_none() {
                    bail!(
                        "metadata.provenance.provenance_index is required when privacy_tier=internal|restricted"
                    );
                }
            }
            None => {}
        }
    }

    Ok(())
}

fn validate_submit_message_metadata(text: &str) -> Result<()> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(());
    };

    let Some(metadata_value) = value.get("metadata") else {
        return Ok(());
    };

    let metadata: TaskMetadata = serde_json::from_value(metadata_value.clone())
        .map_err(|err| anyhow!("invalid metadata payload: {}", err))?;

    validate_task_metadata_core_fields(&metadata)
}

fn transition_request_status(current: &str, to: RequestStatus) -> Result<String> {
    let from = RequestStatus::parse(current).map_err(|e| anyhow::anyhow!("{}", e))?;
    let next = from.transition(to).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(next.as_str().to_string())
}

fn account_state_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_ACCOUNTS_FILE") {
        return path;
    }
    run_root().join("run/rpc/accounts.json")
}

fn load_account_state(path: &Path) -> BTreeMap<String, AccountState> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str::<BTreeMap<String, AccountState>>(&raw).unwrap_or_default()
}

fn save_account_state(path: &Path, accounts: &BTreeMap<String, AccountState>) -> Result<()> {
    let content = serde_json::to_string_pretty(accounts)?;
    atomic_write_text_file(path, &content)
}

fn tx_lifecycle_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_TX_FILE") {
        return path;
    }
    run_root().join("run/rpc/txs.json")
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FaucetRateEntry {
    window_start_unix_ms: u128,
    count_in_window: u32,
}

fn faucet_limits_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_FAUCET_LIMITS_FILE") {
        return path;
    }
    run_root().join("run/rpc/faucet_limits.json")
}

fn load_faucet_limits(path: &Path) -> BTreeMap<String, FaucetRateEntry> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str::<BTreeMap<String, FaucetRateEntry>>(&raw).unwrap_or_default()
}

fn save_faucet_limits(path: &Path, limits: &BTreeMap<String, FaucetRateEntry>) -> Result<()> {
    let content = serde_json::to_string_pretty(limits)?;
    atomic_write_text_file(path, &content)
}

fn load_tx_lifecycle(path: &Path) -> BTreeMap<String, TxLifecycleRecord> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<BTreeMap<String, TxLifecycleRecord>>(&raw) {
        Ok(txs) => txs,
        Err(err) => {
            eprintln!(
                "[trnm-rpc][warn][TX_LIFECYCLE_PARSE] path={} err={}",
                path.display(),
                err
            );
            BTreeMap::new()
        }
    }
}

fn save_tx_lifecycle(path: &Path, txs: &BTreeMap<String, TxLifecycleRecord>) -> Result<()> {
    let content = serde_json::to_string_pretty(txs)?;
    atomic_write_text_file(path, &content)
}

fn accounts_to_ledger(accounts: &BTreeMap<String, AccountState>) -> InMemoryTransferLedger {
    let mut ledger = InMemoryTransferLedger::new();
    for account in accounts.values() {
        ledger.set_account(account.address.clone(), account.balance, account.nonce);
    }
    ledger
}

fn ledger_to_accounts(
    ledger: &InMemoryTransferLedger,
    accounts: &mut BTreeMap<String, AccountState>,
) {
    for account in accounts.values_mut() {
        account.balance = ledger.balance_of(&account.address);
        account.nonce = ledger.next_nonce_of(&account.address);
    }
}

fn rpc_fail(err: RpcErrorResponse) -> anyhow::Error {
    let body = serde_json::to_string_pretty(&err).unwrap_or_else(|_| {
        format!(
            "{{\"code\":\"{}\",\"message\":\"{}\"}}",
            err.code, err.message
        )
    });
    anyhow::anyhow!(body)
}

fn clamp_limit(op: &str, requested: usize, default_limit: usize, max_limit: usize) -> usize {
    let clamped_default = default_limit.min(max_limit);
    if requested == 0 {
        eprintln!(
            "[trnm-rpc][warn][RPC_CAP] op={} requested_limit=0 fallback_default={} max={}",
            op, clamped_default, max_limit
        );
        return clamped_default;
    }
    if requested > max_limit {
        eprintln!(
            "[trnm-rpc][warn][RPC_CAP] op={} requested_limit={} clamped_limit={} max={}",
            op, requested, max_limit, max_limit
        );
        return max_limit;
    }
    requested
}

fn push_tail_limited<T>(items: &mut Vec<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    items.push(item);
    if items.len() > limit {
        let keep_from = items.len() - limit;
        items.drain(0..keep_from);
    }
}

fn normalize_tx_hash_lookup(raw: &str) -> String {
    let mut normalized = raw.trim_matches(|c: char| {
        c.is_ascii_whitespace() || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
    });

    loop {
        let is_wrapped = normalized.len() >= 2
            && ["\"", "'", "`"]
                .iter()
                .any(|q| normalized.starts_with(q) && normalized.ends_with(q));

        if is_wrapped {
            normalized = normalized[1..normalized.len() - 1].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
            });
            continue;
        }
        break;
    }

    let normalized = normalized.to_ascii_lowercase();
    for delimiter in ['=', ':'] {
        if let Some((k, v)) = normalized.split_once(delimiter) {
            let key = k.trim();
            let normalized_key: String =
                key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if normalized_key == "txhash" || normalized_key == "hash" {
                let mut value = v.trim_matches(|c: char| {
                    c.is_ascii_whitespace()
                        || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
                });
                while let Some(stripped) = value.strip_prefix('=') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                while let Some(stripped) = value.strip_prefix(':') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                loop {
                    let is_wrapped = value.len() >= 2
                        && ["\"", "'", "`"]
                            .iter()
                            .any(|q| value.starts_with(q) && value.ends_with(q));
                    if is_wrapped {
                        value = value[1..value.len() - 1].trim_matches(|c: char| {
                            c.is_ascii_whitespace()
                                || matches!(c, ',' | ';' | '.' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
                        });
                        continue;
                    }
                    break;
                }
                return value.to_string();
            }
        }
    }

    normalized
}

fn is_hex_like_tx_hash(raw: &str) -> bool {
    raw.strip_prefix("0x")
        .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

fn resolve_ops_window(
    window: Option<OpsWindowArg>,
    from_unix_ms: Option<u128>,
    to_unix_ms: Option<u128>,
    now_unix_ms: u128,
) -> Result<Option<(u128, u128, String)>> {
    match window {
        None => Ok(None),
        Some(OpsWindowArg::H24) => Ok(Some((
            now_unix_ms.saturating_sub(24 * 60 * 60 * 1000),
            now_unix_ms,
            "24h".to_string(),
        ))),
        Some(OpsWindowArg::D7) => Ok(Some((
            now_unix_ms.saturating_sub(7 * 24 * 60 * 60 * 1000),
            now_unix_ms,
            "7d".to_string(),
        ))),
        Some(OpsWindowArg::Custom) => {
            let from = from_unix_ms
                .ok_or_else(|| anyhow!("--from-unix-ms is required when --window custom"))?;
            let to = to_unix_ms
                .ok_or_else(|| anyhow!("--to-unix-ms is required when --window custom"))?;
            if from > to {
                bail!("invalid custom window: from_unix_ms ({from}) must be <= to_unix_ms ({to})");
            }
            let span = to.saturating_sub(from);
            if span > OPS_WINDOW_CUSTOM_MAX_MS {
                bail!(
                    "custom window too large: span_ms ({span}) exceeds max_ms ({OPS_WINDOW_CUSTOM_MAX_MS})"
                );
            }
            Ok(Some((from, to, "custom".to_string())))
        }
    }
}

fn summarize_challenge_treasury(
    node_events: &[NodeEventRecord],
    limit: usize,
    summary_window: Option<(u128, u128, String)>,
    node_event_source_mode: NodeEventScanMode,
    node_event_log_truncated: bool,
) -> ChallengeTreasuryQueryResponse {
    let mut related: Vec<&NodeEventRecord> = node_events
        .iter()
        .filter(|e| {
            e.event_type == "challenge"
                || ((e.event_type == "resolve" || e.event_type == "timeout")
                    && matches!(
                        e.bond_disposition.as_deref(),
                        Some("forfeited") | Some("refunded")
                    ))
        })
        .collect();

    related.sort_by_key(|e| (e.block_height, e.tx_id, e.ts_unix_ms));

    let mut posted_by_task = BTreeMap::<u64, u128>::new();
    let mut posted_open_in_window = BTreeMap::<u64, ()>::new();
    let mut escrow_balance: u128 = 0;
    let mut forfeits_balance: u128 = 0;
    let mut cumulative_forfeited: u128 = 0;

    let mut summary_posted: usize = 0;
    let mut summary_refunded: usize = 0;
    let mut summary_forfeited: usize = 0;

    let mut views = Vec::new();
    let mut anomalies = Vec::new();
    let mut seen_event_fingerprints = HashSet::<(
        String,
        u64,
        u64,
        Option<String>,
        Option<String>,
        Option<i128>,
    )>::new();
    for e in &related {
        let mut bond_amount: u128 = 0;
        let mut escrow_delta: i128 = 0;
        let mut forfeits_delta: u128 = 0;

        let in_window = summary_window
            .as_ref()
            .map(|(from, to, _)| e.ts_unix_ms >= *from && e.ts_unix_ms <= *to)
            .unwrap_or(false);

        let fingerprint = (
            e.event_type.clone(),
            e.task_id,
            e.tx_id,
            e.bond_disposition.clone(),
            e.resolution_code.clone(),
            e.challenger_delta,
        );
        if !seen_event_fingerprints.insert(fingerprint) {
            anomalies.push(ChallengeTreasuryAnomaly {
                event_type: e.event_type.clone(),
                task_id: e.task_id,
                tx_id: e.tx_id,
                code: "duplicate_event_replay".to_string(),
                detail: "event replay ignored because an equivalent challenge treasury event was already applied".to_string(),
            });
            views.push(ChallengeTreasuryEventView {
                event_type: e.event_type.clone(),
                task_id: e.task_id,
                tx_id: e.tx_id,
                block_height: e.block_height,
                ts_unix_ms: e.ts_unix_ms,
                challenger: e.challenger.clone(),
                bond_disposition: e.bond_disposition.clone(),
                bond_amount: 0,
                escrow_delta: 0,
                forfeits_delta: 0,
            });
            continue;
        }

        match e.event_type.as_str() {
            "challenge" => {
                bond_amount = e
                    .challenger_delta
                    .filter(|v| *v < 0)
                    .and_then(|v| u128::try_from(v.saturating_abs()).ok())
                    .unwrap_or(0);
                if bond_amount > 0 {
                    if let Some(existing_bond) = posted_by_task.get(&e.task_id).copied() {
                        anomalies.push(ChallengeTreasuryAnomaly {
                            event_type: e.event_type.clone(),
                            task_id: e.task_id,
                            tx_id: e.tx_id,
                            code: "duplicate_open_challenge".to_string(),
                            detail: format!(
                                "challenge ignored because task already has unresolved posted bond {}",
                                existing_bond
                            ),
                        });
                        bond_amount = 0;
                    } else {
                        posted_by_task.insert(e.task_id, bond_amount);
                        escrow_balance = escrow_balance.saturating_add(bond_amount);
                        escrow_delta = i128::try_from(bond_amount).ok().unwrap_or(i128::MAX);
                        if in_window {
                            summary_posted = summary_posted.saturating_add(1);
                            posted_open_in_window.insert(e.task_id, ());
                        }
                    }
                } else if e.challenger_delta.unwrap_or(0) != 0 {
                    anomalies.push(ChallengeTreasuryAnomaly {
                        event_type: e.event_type.clone(),
                        task_id: e.task_id,
                        tx_id: e.tx_id,
                        code: "invalid_challenge_delta_sign".to_string(),
                        detail: format!(
                            "challenge ignored because challenger_delta must be negative, got {}",
                            e.challenger_delta.unwrap_or(0)
                        ),
                    });
                }
            }
            "resolve" | "timeout" => match e.bond_disposition.as_deref() {
                Some("forfeited") => {
                    let maybe_bond = posted_by_task.remove(&e.task_id).unwrap_or(0);
                    bond_amount = maybe_bond;
                    if maybe_bond > 0 {
                        escrow_balance = escrow_balance.saturating_sub(maybe_bond);
                        forfeits_balance = forfeits_balance.saturating_add(maybe_bond);
                        cumulative_forfeited = cumulative_forfeited.saturating_add(maybe_bond);
                        escrow_delta = -i128::try_from(maybe_bond).ok().unwrap_or(i128::MAX);
                        forfeits_delta = maybe_bond;
                        if in_window {
                            summary_forfeited = summary_forfeited.saturating_add(1);
                        }
                    } else {
                        anomalies.push(ChallengeTreasuryAnomaly {
                                event_type: e.event_type.clone(),
                                task_id: e.task_id,
                                tx_id: e.tx_id,
                                code: "resolve_without_posted_bond".to_string(),
                                detail: "forfeited resolve ignored because no prior posted challenge bond found".to_string(),
                            });
                    }
                    posted_open_in_window.remove(&e.task_id);
                }
                Some("refunded") => {
                    let maybe_bond = posted_by_task.remove(&e.task_id).unwrap_or(0);
                    bond_amount = maybe_bond;
                    if maybe_bond > 0 {
                        escrow_balance = escrow_balance.saturating_sub(maybe_bond);
                        escrow_delta = -i128::try_from(maybe_bond).ok().unwrap_or(i128::MAX);
                        if in_window {
                            summary_refunded = summary_refunded.saturating_add(1);
                        }
                    } else {
                        anomalies.push(ChallengeTreasuryAnomaly {
                                event_type: e.event_type.clone(),
                                task_id: e.task_id,
                                tx_id: e.tx_id,
                                code: "resolve_without_posted_bond".to_string(),
                                detail: "refunded resolve ignored because no prior posted challenge bond found".to_string(),
                            });
                    }
                    posted_open_in_window.remove(&e.task_id);
                }
                _ => {}
            },
            _ => {}
        }

        views.push(ChallengeTreasuryEventView {
            event_type: e.event_type.clone(),
            task_id: e.task_id,
            tx_id: e.tx_id,
            block_height: e.block_height,
            ts_unix_ms: e.ts_unix_ms,
            challenger: e.challenger.clone(),
            bond_disposition: e.bond_disposition.clone(),
            bond_amount,
            escrow_delta,
            forfeits_delta,
        });
    }

    let events_total = views.len();
    if views.len() > limit {
        let keep_from = views.len() - limit;
        views = views.split_off(keep_from);
    }

    let daily_summary = summary_window.as_ref().map(|_| ChallengeDailySummary {
        posted: summary_posted,
        refunded: summary_refunded,
        forfeited: summary_forfeited,
        unresolved: posted_open_in_window.len(),
    });

    let window = summary_window.map(|(from, to, mode)| ChallengeWindowView {
        mode,
        from_unix_ms: from,
        to_unix_ms: to,
    });

    ChallengeTreasuryQueryResponse {
        challenge_escrow_account: CHALLENGE_ESCROW_ACCOUNT.to_string(),
        challenge_forfeits_account: CHALLENGE_FORFEIT_TREASURY_ACCOUNT.to_string(),
        current_escrow_balance: escrow_balance,
        current_forfeits_balance: forfeits_balance,
        cumulative_forfeited,
        events_total,
        events: views,
        anomaly_count: anomalies.len(),
        anomalies,
        daily_summary,
        window,
        node_event_source_mode: node_event_source_mode.as_str().to_string(),
        node_event_log_truncated,
    }
}

fn is_health_probe_path(path: &str) -> bool {
    [
        "/health",
        "/health/",
        "/healthz",
        "/healthz/",
        "/live",
        "/live/",
        "/livez",
        "/livez/",
        "/ready",
        "/ready/",
        "/readyz",
        "/readyz/",
        "/status",
        "/status/",
        "/statusz",
        "/statusz/",
        "/-/health",
        "/-/health/",
        "/-/healthz",
        "/-/healthz/",
        "/-/live",
        "/-/live/",
        "/-/livez",
        "/-/livez/",
        "/-/ready",
        "/-/ready/",
        "/-/readyz",
        "/-/readyz/",
        "/-/status",
        "/-/status/",
        "/-/statusz",
        "/-/statusz/",
    ]
    .iter()
    .any(|alias| path.eq_ignore_ascii_case(alias))
}

fn is_supported_http_version(version: &str) -> bool {
    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn http_json_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn http_json_head_response(status_line: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    )
}

fn http_response_for_method(method: &str, response: &str) -> String {
    if method != "HEAD" {
        return response.to_string();
    }

    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return response.to_string();
    };

    let mut rebuilt = String::new();
    for (idx, line) in headers.split("\r\n").enumerate() {
        if idx > 0 && line.to_ascii_lowercase().starts_with("content-length:") {
            rebuilt.push_str(&format!("Content-Length: {}\r\n", body.len()));
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str("\r\n");
    rebuilt
}

fn configure_health_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(HEALTH_SOCKET_WRITE_TIMEOUT_MS)))?;
    Ok(())
}

fn read_http_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    while buf.len() < HEALTH_REQUEST_HEADER_MAX_BYTES {
        let remaining = HEALTH_REQUEST_HEADER_MAX_BYTES - buf.len();
        let to_read = remaining.min(chunk.len());
        let n = stream.read(&mut chunk[..to_read])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP request header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n")
            || buf.windows(2).any(|window| window == b"\n\n")
        {
            return Ok(buf);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "HTTP request header too large",
    ))
}

fn parse_http_request_target(first_line: &str) -> Option<(&str, &str)> {
    let line = first_line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }

    let first_sp = line.find(' ')?;
    let method = &line[..first_sp];
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }

    let mut rest = line[first_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return None;
    }

    let second_sp = rest.find(' ')?;
    let path = &rest[..second_sp];
    if !path.starts_with('/') {
        return None;
    }
    rest = rest[second_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() || rest.contains([' ', '\t']) || !is_supported_http_version(rest) {
        return None;
    }

    let normalized = path.to_ascii_lowercase();
    if path.contains('\\') || normalized.contains("%5c") {
        return None;
    }
    if path.contains('#') || normalized.contains("%23") {
        return None;
    }
    if normalized.contains("%00")
        || normalized.contains("%0d")
        || normalized.contains("%0a")
        || normalized.contains("%09")
        || normalized.contains("%0b")
        || normalized.contains("%0c")
        || normalized.contains("%20")
        || normalized.contains("%7f")
    {
        return None;
    }

    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    if normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }

    Some((method, path))
}

#[cfg(test)]
fn parse_http_get_path(first_line: &str) -> Option<&str> {
    match parse_http_request_target(first_line) {
        Some((method, path)) if method.eq_ignore_ascii_case("GET") => {
            Some(path.split('?').next().unwrap_or(path))
        }
        _ => None,
    }
}

fn parse_query_events_limit_from_path(path: &str) -> std::result::Result<usize, String> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    if !path_without_query.starts_with('/')
        || path_without_query.contains('\\')
        || path_without_query.contains('#')
        || normalized_path.contains("%5c")
        || normalized_path.contains("%23")
        || normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || normalized_path.contains("%00")
        || normalized_path.contains("%0d")
        || normalized_path.contains("%0a")
        || normalized_path.contains("%09")
        || normalized_path.contains("%0b")
        || normalized_path.contains("%0c")
        || normalized_path.contains("%20")
        || normalized_path.contains("%7f")
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }

    let Some(query) = path.split_once('?').map(|(_, query)| query) else {
        return Ok(QUERY_EVENTS_LIMIT_DEFAULT);
    };

    if query.is_empty()
        || query.contains('?')
        || query.contains('#')
        || query.chars().any(|ch| ch.is_control())
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }
    let normalized_query = query.to_ascii_lowercase();
    if normalized_query.contains("%26")
        || normalized_query.contains("%3d")
        || normalized_query.contains("%23")
        || normalized_query.contains("%3f")
        || normalized_query.contains("%0d")
        || normalized_query.contains("%0a")
        || normalized_query.contains("%09")
        || normalized_query.contains("%0b")
        || normalized_query.contains("%0c")
        || normalized_query.contains("%20")
    {
        return Err(http_json_response(
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
        ));
    }

    let mut parsed_limit: Option<usize> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        };
        let normalized_key = normalize_wrapped_env_value(key);
        if !normalized_key.eq_ignore_ascii_case("limit") || key != "limit" {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }
        if parsed_limit.is_some() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"duplicate limit\"}",
            ));
        }

        let normalized = normalize_wrapped_env_value(value);
        if normalized.is_empty() {
            return Err(http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            ));
        }

        let requested = normalized.parse::<usize>().map_err(|_| {
            http_json_response(
                "400 Bad Request",
                "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid limit\"}",
            )
        })?;
        parsed_limit = Some(clamp_limit(
            "QueryEventsHttp",
            requested,
            QUERY_EVENTS_LIMIT_DEFAULT,
            QUERY_EVENTS_LIMIT_MAX,
        ));
    }

    Ok(parsed_limit.unwrap_or(QUERY_EVENTS_LIMIT_DEFAULT))
}

fn contains_malformed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return true;
            }
            let hi = (bytes[idx + 1] as char).to_digit(16);
            let lo = (bytes[idx + 2] as char).to_digit(16);
            if hi.is_none() || lo.is_none() {
                return true;
            }
            idx += 3;
            continue;
        }
        idx += 1;
    }
    false
}

fn parse_query_normalized_audit_events_query_from_path(
    path: &str,
) -> std::result::Result<QueryNormalizedAuditEventsQuery, String> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let normalized_path = path_without_query.to_ascii_lowercase();
    if !path_without_query.starts_with('/')
        || path_without_query != "/query-normalized-audit-events"
        || path_without_query.contains('\x5c')
        || path_without_query.contains('#')
        || normalized_path.contains("%5c")
        || normalized_path.contains("%23")
        || normalized_path.contains("%2f")
        || normalized_path.contains("%2e")
        || normalized_path.contains("%00")
        || normalized_path.contains("%0d")
        || normalized_path.contains("%0a")
        || normalized_path.contains("%09")
        || normalized_path.contains("%0b")
        || normalized_path.contains("%0c")
        || normalized_path.contains("%20")
        || normalized_path.contains("%7f")
        || contains_malformed_percent_encoding(path_without_query)
        || path_without_query
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(http_json_response(
            "400 Bad Request",
            r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
        ));
    }

    let Some(query) = path.split_once('?').map(|(_, query)| query) else {
        return Ok(QueryNormalizedAuditEventsQuery {
            source: None,
            event_type: None,
            cursor: None,
            limit: QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
        });
    };

    if query.is_empty()
        || query.contains('?')
        || query.contains('#')
        || query.chars().any(|ch| ch.is_control())
    {
        return Err(http_json_response(
            "400 Bad Request",
            r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
        ));
    }

    let normalized_query = query.to_ascii_lowercase();
    if normalized_query.contains("%26")
        || normalized_query.contains("%3d")
        || normalized_query.contains("%23")
        || normalized_query.contains("%3f")
        || normalized_query.contains("%00")
        || normalized_query.contains("%0d")
        || normalized_query.contains("%0a")
        || normalized_query.contains("%09")
        || normalized_query.contains("%0b")
        || normalized_query.contains("%0c")
        || normalized_query.contains("%20")
        || normalized_query.contains("%7f")
        || contains_malformed_percent_encoding(query)
    {
        return Err(http_json_response(
            "400 Bad Request",
            r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
        ));
    }

    let mut query_params = QueryNormalizedAuditEventsQuery {
        source: None,
        event_type: None,
        cursor: None,
        limit: QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
    };
    let mut parsed_limit: Option<usize> = None;

    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(http_json_response(
                "400 Bad Request",
                r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
            ));
        }

        let Some((key, value)) = pair.split_once('=') else {
            return Err(http_json_response(
                "400 Bad Request",
                r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
            ));
        };

        let normalized_key = normalize_wrapped_env_value(key);
        match normalized_key {
            key if key.eq_ignore_ascii_case("source") && key == "source" => {
                if query_params.source.is_some() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate source"}"#,
                    ));
                }
                let normalized = normalize_wrapped_env_value(value);
                if normalized.is_empty() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid source"}"#,
                    ));
                }
                query_params.source = Some(normalized.to_string());
            }
            key if key.eq_ignore_ascii_case("eventType") && key == "eventType" => {
                if query_params.event_type.is_some() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate eventType"}"#,
                    ));
                }
                let normalized = normalize_wrapped_env_value(value);
                if normalized.is_empty() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid eventType"}"#,
                    ));
                }
                query_params.event_type = Some(normalized.to_string());
            }
            key if key.eq_ignore_ascii_case("cursor") && key == "cursor" => {
                if query_params.cursor.is_some() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate cursor"}"#,
                    ));
                }
                let normalized = normalize_wrapped_env_value(value);
                if normalized.is_empty() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid cursor"}"#,
                    ));
                }
                let parsed = normalized.parse::<usize>().map_err(|_| {
                    http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid cursor"}"#,
                    )
                })?;
                query_params.cursor = Some(parsed);
            }
            key if key.eq_ignore_ascii_case("limit") && key == "limit" => {
                if parsed_limit.is_some() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"duplicate limit"}"#,
                    ));
                }
                let normalized = normalize_wrapped_env_value(value);
                if normalized.is_empty() {
                    return Err(http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid limit"}"#,
                    ));
                }
                let requested = normalized.parse::<usize>().map_err(|_| {
                    http_json_response(
                        "400 Bad Request",
                        r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid limit"}"#,
                    )
                })?;
                parsed_limit = Some(clamp_limit(
                    "QueryNormalizedAuditEventsHttp",
                    requested,
                    QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
                    QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX,
                ));
            }
            _ => {
                return Err(http_json_response(
                    "400 Bad Request",
                    r#"{"ok":false,"code":"BAD_REQUEST","message":"invalid query"}"#,
                ));
            }
        }
    }

    if let Some(limit) = parsed_limit {
        query_params.limit = limit;
    }

    Ok(query_params)
}

fn normalize_capability_subject_lookup(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .chars()
        .filter_map(|ch| match ch {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' => None,
            _ if ch.is_control() => None,
            _ => Some(ch),
        })
        .collect::<String>();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn resolve_capability_token_subject_or_token(
    registry: &IdentityRegistry,
    subject_or_token: &str,
) -> Option<u64> {
    let normalized = normalize_capability_subject_lookup(subject_or_token)?;
    if let Ok(token_id) = normalized.parse::<u64>() {
        return Some(token_id);
    }

    if !IdentityRegistry::is_canonical_did(&normalized) {
        return None;
    }

    let mut subject_tokens = registry
        .capability_ids_by_subject(&normalized)
        .into_iter()
        .filter(|token_id| {
            registry
                .capability(*token_id)
                .map(|token| token.subject_did == normalized)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    subject_tokens.sort_unstable();
    subject_tokens.last().copied()
}

fn json_response_for_method(method: &str, status_line: &str, body: &str) -> String {
    if method.eq_ignore_ascii_case("HEAD") {
        http_json_head_response(status_line, body.len())
    } else {
        http_json_response(status_line, body)
    }
}

fn has_ambiguous_path_segment_encoding(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c")
}

fn parse_nonempty_path_suffix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix)
        .and_then(|suffix| {
            if suffix.is_empty() {
                return None;
            }
            let trimmed = suffix.trim_end_matches('/');
            let trailing_slashes = suffix.len().saturating_sub(trimmed.len());
            if trailing_slashes > 1 {
                return None;
            }
            Some(trimmed)
        })
        .filter(|suffix| !suffix.is_empty())
        .filter(|suffix| !matches!(*suffix, "." | ".."))
        .filter(|suffix| !suffix.contains('/'))
        .filter(|suffix| !suffix.contains('\\'))
        .filter(|suffix| !has_ambiguous_path_segment_encoding(suffix))
}

fn serve_health(host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    eprintln!("[trnm-rpc] service listening on http://{addr}");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if configure_health_stream(&stream).is_err() {
            continue;
        }

        let req = match read_http_request_head(&mut stream) {
            Ok(req) => req,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => continue,
        };
        if req.is_empty() {
            continue;
        }
        let req = String::from_utf8_lossy(&req);
        let first = req.lines().next().unwrap_or("");
        let request = parse_http_request_target(first);
        let target = request.map(|(_, raw)| raw);
        let path = request.map(|(_, raw)| raw.split('?').next().unwrap_or(raw));

        let response = match (request, path, target) {
            (Some((method, _)), Some(path), _) if is_health_probe_path(path) => {
                let body = serde_json::json!({
                    "ok": true,
                    "service": "trnm-rpc",
                    "ts_unix_ms": now_ms(),
                    "version": 1
                })
                .to_string();
                json_response_for_method(method, "200 OK", &body)
            }
            (Some((method, _)), Some(path), Some(_)) if path.starts_with("/query-task/") => {
                let task_id = path
                    .trim_start_matches("/query-task/")
                    .trim_end_matches('/')
                    .parse::<u64>();
                match task_id {
                    Ok(task_id) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        match query_task_response(task_id, &node_events.events, &recs) {
                            Ok(out) => {
                                let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                    "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                });
                                json_response_for_method(method, "200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                json_response_for_method(method, "404 Not Found", &body)
                            }
                        }
                    }
                    Err(_) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            (Some((method, _)), Some(path), Some(target)) if path.starts_with("/query-events/") => {
                let task_id = path
                    .trim_start_matches("/query-events/")
                    .trim_end_matches('/')
                    .parse::<u64>();
                let limit = parse_query_events_limit_from_path(target);
                match (task_id, limit) {
                    (Ok(task_id), Ok(limit)) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        match query_events_response(task_id, limit, &node_events.events, &recs) {
                            Ok(events) => {
                                let body = serde_json::to_string(&events).unwrap_or_else(|_| {
                                    "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                });
                                json_response_for_method(method, "200 OK", &body)
                            }
                            Err(err) => {
                                let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_string()}).to_string();
                                json_response_for_method(method, "404 Not Found", &body)
                            }
                        }
                    }
                    (_, Err(err)) => http_response_for_method(method, &err),
                    (Err(_), _) => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid task_id\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            (Some((method, _)), Some(path), Some(target))
                if path == "/query-normalized-audit-events" =>
            {
                let query = parse_query_normalized_audit_events_query_from_path(target);
                match query {
                    Ok(query) => {
                        let node_events = load_node_events(NodeEventScanMode::Authoritative);
                        let recs = load_latest_adapter_records();
                        let out = query_normalized_audit_events(&node_events.events, &recs, &query);
                        let body = serde_json::to_string(&out)
                            .unwrap_or_else(|_| r#"{"ok":false,"code":"SERDE_ERROR"}"#.to_string());
                        json_response_for_method(method, "200 OK", &body)
                    }
                    Err(err) => err,
                }
            }

            (Some((method, _)), Some(path), Some(_))
                if path.starts_with("/query-capability-audit/") =>
            {
                match parse_nonempty_path_suffix(path, "/query-capability-audit/") {
                    Some(subject_or_token) => {
                        let registry = load_identity_registry(&identity_registry_file());
                        if let Some(token_id) =
                            resolve_capability_token_subject_or_token(&registry, subject_or_token)
                        {
                            match query_capability_audit(&registry, token_id) {
                                Ok(out) => {
                                    let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                        "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                    });
                                    json_response_for_method(method, "200 OK", &body)
                                }
                                Err(err) => {
                                    let body = serde_json::json!({"ok": false, "code": "NOT_FOUND", "message": err.to_rpc_error().message}).to_string();
                                    json_response_for_method(method, "404 Not Found", &body)
                                }
                            }
                        } else {
                            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\",\"message\":\"token or subject not found\"}";
                            json_response_for_method(method, "404 Not Found", body)
                        }
                    }
                    None => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"missing token or subject\"}";
                        json_response_for_method(method, "400 Bad Request", body)
                    }
                }
            }
            _ => {
                match request {
                    Some((method, _)) => {
                        let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
                        json_response_for_method(method, "404 Not Found", body)
                    }
                    None => {
                        let body = "{\"ok\":false,\"code\":\"BAD_REQUEST\",\"message\":\"invalid http request\"}";
                        http_json_response("400 Bad Request", body)
                    }
                }
            }
        };

        let _ = stream.write_all(response.as_bytes());
    }

    Ok(())
}

fn task_status_from_node_status(status: &str) -> Option<TaskStatus> {
    match status {
        "Open" => Some(TaskStatus::Open),
        "Assigned" => Some(TaskStatus::Assigned),
        "Committed" => Some(TaskStatus::Committed),
        "Revealed" => Some(TaskStatus::Revealed),
        "Challenged" => Some(TaskStatus::Challenged),
        "Completed" => Some(TaskStatus::Completed),
        "Slashed" => Some(TaskStatus::Slashed),
        _ => None,
    }
}

fn is_legal_node_event_transition(event_type: &str, from_status: &str, to_status: &str) -> bool {
    matches!(
        (event_type, from_status, to_status),
        ("create", "NONE", "Open")
            | ("accept", "Open", "Assigned")
            | ("commit", "Assigned", "Committed")
            | ("reveal", "Committed", "Revealed")
            | ("challenge", "Revealed", "Challenged")
            | ("resolve", "Challenged", "Completed")
            | ("resolve", "Challenged", "Slashed")
            | ("timeout", "Committed", "Slashed")
            | ("timeout", "Revealed", "Completed")
            | ("timeout", "Challenged", "Completed")
    )
}

fn is_trusted_event_source(event: &NodeEventRecord) -> bool {
    let Some(actor) = normalize_actor_or_signer(&event.actor) else {
        return false;
    };
    let signer = event
        .signer
        .as_deref()
        .and_then(normalize_actor_or_signer)
        .unwrap_or_else(|| actor.clone());

    match event.event_type.as_str() {
        "accept" | "commit" | "reveal" | "challenge" | "create" => signer == actor,
        // Hardening: terminal resolve events must be adjudicated by governance
        // authority only; reserve `system` for timeout automation paths.
        "resolve" => signer == actor && actor == "authority",
        "timeout" => signer == actor && matches!(actor.as_str(), "authority" | "system"),
        _ => false,
    }
}

fn filtered_node_events_for_task<'a>(
    task_id: u64,
    node_events: &'a [NodeEventRecord],
) -> impl Iterator<Item = &'a NodeEventRecord> {
    node_events.iter().filter(move |event| {
        event.task_id == task_id
            && is_legal_node_event_transition(
                event.event_type.as_str(),
                event.from_status.as_str(),
                event.to_status.as_str(),
            )
            && is_trusted_event_source(event)
    })
}

fn query_task_from_node_events(
    task_id: u64,
    node_events: &[NodeEventRecord],
) -> Option<TaskQueryResponse> {
    let mut version: u64 = 0;
    let mut status: Option<TaskStatus> = None;
    let mut worker: Option<String> = None;

    for event in filtered_node_events_for_task(task_id, node_events) {
        version += 1;
        if let Some(mapped) = task_status_from_node_status(event.to_status.as_str()) {
            status = Some(mapped);
        }
        if event.event_type == "accept"
            || event.event_type == "commit"
            || event.event_type == "reveal"
        {
            worker = normalize_actor_or_signer(&event.actor);
        }
    }

    status.map(|status| TaskQueryResponse {
        task_id,
        status,
        worker,
        bounty: 100,
        result_hash_hex: None,
        version,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    })
}

fn query_task_response(
    task_id: u64,
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
) -> Result<TaskQueryResponse> {
    let task_state_snapshot = load_task_state_snapshot()?;
    if let Some(out) = query_task_from_state_snapshot(task_id, &task_state_snapshot) {
        return Ok(out);
    }
    if let Some(out) = query_task_from_node_events(task_id, node_events) {
        return Ok(out);
    }

    let task_recs: Vec<&AdapterRecord> = recs
        .iter()
        .filter(|r| {
            r.task_id == task_id
                && r.status == "accepted"
                && matches!(r.kind.as_str(), "commit" | "reveal")
                && r.worker
                    .as_deref()
                    .and_then(normalize_actor_or_signer)
                    .is_some()
        })
        .collect();
    if task_recs.is_empty() {
        bail!("task not found: {}", task_id);
    }
    let has_reveal = task_recs.iter().any(|r| r.kind == "reveal");
    let has_commit = task_recs.iter().any(|r| r.kind == "commit");
    let status = if has_reveal {
        TaskStatus::Revealed
    } else if has_commit {
        TaskStatus::Committed
    } else {
        TaskStatus::Open
    };
    let worker = task_recs.iter().find_map(|r| r.worker.clone());
    let result_hash_hex = task_recs.iter().rev().find_map(|r| {
        if r.kind == "reveal" {
            r.result_hash.clone()
        } else {
            None
        }
    });
    Ok(TaskQueryResponse {
        task_id,
        status,
        worker,
        bounty: 100,
        result_hash_hex,
        version: task_recs.len() as u64,
        metadata_compatibility: None,
        metadata_runtime_compatible: None,
        metadata_requires_governance_upgrade: None,
        metadata_primary_compatibility_finding: None,
        metadata_compatibility_findings: None,
        metering: None,
    })
}

fn query_events_response(
    task_id: u64,
    limit: usize,
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
) -> Result<Vec<EventQueryResponse>> {
    let limit = clamp_limit(
        "QueryEvents",
        limit,
        QUERY_EVENTS_LIMIT_DEFAULT,
        QUERY_EVENTS_LIMIT_MAX,
    );
    let mut events = Vec::new();

    for e in filtered_node_events_for_task(task_id, node_events) {
        let Some(actor) = normalize_actor_or_signer(&e.actor) else {
            continue;
        };
        let signer = e
            .signer
            .as_deref()
            .and_then(normalize_actor_or_signer)
            .or_else(|| Some(actor.clone()));
        push_tail_limited(
            &mut events,
            EventQueryResponse {
                event_type: e.event_type.clone(),
                task_id,
                from_status: e.from_status.clone(),
                to_status: e.to_status.clone(),
                actor,
                tx_id: e.tx_id,
                block_height: e.block_height,
                state_root: e.state_root.clone(),
                ts_unix_ms: e.ts_unix_ms,
                signer,
                challenger: e.challenger.clone(),
                tx_hash: e.tx_hash.clone(),
                resolution_code: e.resolution_code.clone(),
                treasury_delta: e.treasury_delta,
                challenger_delta: e.challenger_delta,
                bond_disposition: e.bond_disposition.clone(),
                metering: e.metering.clone(),
            },
            limit,
        );
    }

    if events.is_empty() {
        let mut tx_id = 1u64;
        let mut has_commit = false;
        for r in recs
            .iter()
            .filter(|r| r.task_id == task_id && r.status == "accepted")
        {
            let Some(actor) = r.worker.as_deref().and_then(normalize_actor_or_signer) else {
                continue;
            };
            let kind = r.kind.clone();
            if kind == "reveal" && !has_commit {
                continue;
            }
            let Some((from_status, to_status)) = (match kind.as_str() {
                "commit" => Some(("Assigned".to_string(), "Committed".to_string())),
                "reveal" => Some(("Committed".to_string(), "Revealed".to_string())),
                _ => None,
            }) else {
                continue;
            };

            let tx_hash = r.tx_hash.clone().and_then(|v| {
                let normalized = normalize_tx_hash_lookup(&v);
                if is_hex_like_tx_hash(&normalized) {
                    Some(normalized)
                } else {
                    None
                }
            });

            push_tail_limited(
                &mut events,
                EventQueryResponse {
                    event_type: kind.clone(),
                    task_id,
                    from_status,
                    to_status,
                    actor: actor.clone(),
                    tx_id,
                    block_height: tx_id,
                    state_root: "adapter_state".into(),
                    ts_unix_ms: r.ts as u128,
                    signer: Some(actor),
                    challenger: None,
                    tx_hash,
                    resolution_code: None,
                    treasury_delta: None,
                    challenger_delta: None,
                    bond_disposition: None,
                    metering: None,
                },
                limit,
            );
            if kind == "commit" {
                has_commit = true;
            }
            tx_id += 1;
        }
    }

    if events.is_empty() {
        bail!("events not found for task_id={}", task_id);
    }
    Ok(events)
}

fn query_normalized_audit_events(
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
    query: &QueryNormalizedAuditEventsQuery,
) -> QueryNormalizedAuditEventsResponse {
    let mut events: Vec<NormalizedAuditEvent> = Vec::new();
    let limit = clamp_limit(
        "QueryNormalizedAuditEvents",
        query.limit,
        QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
        QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX,
    );

    for e in node_events {
        if !is_legal_node_event_transition(&e.event_type, &e.from_status, &e.to_status)
            || !is_trusted_event_source(e)
        {
            continue;
        }

        let Some(actor) = normalize_actor_or_signer(&e.actor) else {
            continue;
        };

        let event_type = format!("trnm.task.{}", e.event_type);
        if query
            .source
            .as_deref()
            .is_some_and(|filter| filter != "trnm.task")
        {
            continue;
        }
        if query
            .event_type
            .as_deref()
            .is_some_and(|filter| filter != event_type)
        {
            continue;
        }

        let reason = Some(format!("{} -> {}", e.from_status, e.to_status));
        events.push(NormalizedAuditEvent {
            source: "trnm.task".into(),
            event_type,
            actor: Some(actor),
            object_id: Some(format!("task:{}", e.task_id)),
            related_id: None,
            amount: None,
            reason,
            note: e.resolution_code.clone(),
            checked_at: Some(format!("height:{}", e.block_height)),
            timestamp: None,
            subject: None,
        });
    }

    for rec in recs.iter().filter(|r| r.status == "accepted") {
        let Some(actor) = rec.worker.as_deref().and_then(normalize_actor_or_signer) else {
            continue;
        };

        let event_type = format!("trnm.adapter.{}", rec.kind);
        if query
            .source
            .as_deref()
            .is_some_and(|filter| filter != "trnm.adapter")
        {
            continue;
        }
        if query
            .event_type
            .as_deref()
            .is_some_and(|filter| filter != event_type)
        {
            continue;
        }

        events.push(NormalizedAuditEvent {
            source: "trnm.adapter".into(),
            event_type,
            actor: Some(actor),
            object_id: Some(format!("task:{}", rec.task_id)),
            related_id: None,
            amount: None,
            reason: Some("adapter-event".into()),
            note: rec.tx_hash.clone().or(rec.result_hash.clone()),
            checked_at: Some(format!("height:{}", rec.ts)),
            timestamp: None,
            subject: None,
        });
    }

    events.sort_by(|left, right| {
        let left_height = left
            .checked_at
            .as_deref()
            .and_then(|value| {
                value
                    .strip_prefix("height:")
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(0);
        let right_height = right
            .checked_at
            .as_deref()
            .and_then(|value| {
                value
                    .strip_prefix("height:")
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(0);
        right_height
            .cmp(&left_height)
            .then_with(|| left.event_type.cmp(&right.event_type))
    });

    let total = events.len();
    let start = query.cursor.unwrap_or(0);
    if start >= total {
        return QueryNormalizedAuditEventsResponse {
            events: Vec::new(),
            next_cursor: None,
            has_more: Some(false),
            total: Some(total),
        };
    }

    let end = (start + limit).min(total);
    let has_more = end < total;
    let page = events.into_iter().skip(start).take(limit).collect();

    QueryNormalizedAuditEventsResponse {
        events: page,
        next_cursor: if has_more {
            Some(end.to_string())
        } else {
            None
        },
        has_more: Some(has_more),
        total: Some(total),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let st = governance_state();
    let recs = load_latest_adapter_records();

    match args.cmd {
        Command::QueryTask { task_id } => {
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let out = query_task_response(task_id, &node_events.events, &recs)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryProposal { proposal_id } => {
            let Some(p) = st.get_proposal(proposal_id) else {
                bail!("proposal not found: {}", proposal_id);
            };
            let out = GovProposalQueryResponse {
                proposal_id: p.proposal_id,
                title: p.title,
                proposer: p.proposer,
                status: p.status,
                version: p.version,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryParam { key } => {
            let Some(p) = st.gov_param_snapshot(&key) else {
                bail!("param not found: {}", key);
            };
            let pending_update = st.pending_gov_update(&key).map(|pending| {
                trnm_rpc::PendingGovParamUpdateQueryResponse {
                    key_id: pending.key_id,
                    key: pending.key,
                    value: pending.value,
                    activate_at_height: pending.activate_at_height,
                }
            });
            let out = GovParamQueryResponse {
                key_id: p.key_id,
                key: p.key,
                value: p.value,
                version: p.version,
                pending_update,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryEvents { task_id, limit } => {
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let events = query_events_response(task_id, limit, &node_events.events, &recs)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        Command::QueryCapabilityAudit { token_id } => {
            let registry = load_identity_registry(&identity_registry_file());
            let out = query_capability_audit(&registry, token_id)
                .map_err(|e| rpc_fail(e.to_rpc_error()))?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryChallengeTreasury {
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
        } => {
            let limit = clamp_limit(
                "QueryChallengeTreasury",
                limit,
                CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT,
                CHALLENGE_TREASURY_EVENTS_LIMIT_MAX,
            );
            let summary_window = resolve_ops_window(window, from_unix_ms, to_unix_ms, now_ms())?;
            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let out = summarize_challenge_treasury(
                &node_events.events,
                limit,
                summary_window,
                node_events.mode,
                node_events.truncated,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                // Keep backward compatibility: default remains JSON output.
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Command::QueryBalance { address } => {
            let accounts = load_account_state(&account_state_file());
            let account =
                query_account_state(&accounts, &address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
            let out = AccountBalanceQueryResponse {
                address: account.address,
                balance: account.balance,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryNonce { address } => {
            let accounts = load_account_state(&account_state_file());
            let account =
                query_account_state(&accounts, &address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
            let out = AccountNonceQueryResponse {
                address: account.address,
                nonce: account.nonce,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::SendTx {
            from,
            to,
            amount,
            fee,
            nonce,
            signature,
        } => {
            let tx_path = tx_lifecycle_file();
            let _tx_lock = acquire_market_file_lock(&tx_path)?;
            let mut txs = load_tx_lifecycle(&tx_path);
            let tx = TransferTx {
                from,
                to,
                amount,
                fee,
                nonce,
                signature,
            };
            let out = submit_tx(&mut txs, tx, now_ms());
            save_tx_lifecycle(&tx_path, &txs)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::GetTx { tx_hash } => {
            let tx_path = tx_lifecycle_file();
            let _tx_lock = acquire_market_file_lock(&tx_path)?;
            let mut txs = load_tx_lifecycle(&tx_path);

            let account_path = account_state_file();
            let _account_lock = acquire_market_file_lock(&account_path)?;
            let mut accounts = load_account_state(&account_path);
            let mut ledger = accounts_to_ledger(&accounts);
            let tx_hash = normalize_tx_hash_lookup(&tx_hash);
            if !is_hex_like_tx_hash(&tx_hash) {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "INVALID_ARGUMENT",
                    message: format!(
                        "invalid tx hash format: expected 0x-prefixed hexadecimal, got {}",
                        tx_hash
                    ),
                }));
            }

            let out = get_tx(&mut txs, &mut ledger, &tx_hash, now_ms()).map_err(|e| match e {
                GetTxError::NotFound(tx_hash) => rpc_fail(RpcErrorResponse {
                    code: "TX_NOT_FOUND",
                    message: format!("tx not found: {}", tx_hash),
                }),
            })?;

            ledger_to_accounts(&ledger, &mut accounts);
            save_tx_lifecycle(&tx_path, &txs)?;
            save_account_state(&account_path, &accounts)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::FaucetRequest { address, amount } => {
            let window_seconds = env_u64_with_min(
                "TRNM_RPC_FAUCET_WINDOW_SECONDS",
                FAUCET_WINDOW_SECONDS_DEFAULT,
                FAUCET_WINDOW_SECONDS_MIN,
            );
            let max_requests_in_window = env_u32_with_min(
                "TRNM_RPC_FAUCET_MAX_REQUESTS",
                FAUCET_MAX_REQUESTS_DEFAULT,
                FAUCET_MAX_REQUESTS_MIN,
            );
            let now = now_ms();

            if validate_trnm_address(&address).is_err() {
                let out = FaucetRequestResponse {
                    ok: false,
                    code: "INVALID_ADDRESS".into(),
                    message: format!("invalid address format: {}", address),
                    address,
                    requested_amount: amount,
                    granted_amount: 0,
                    balance: None,
                    nonce: None,
                    window_seconds,
                    next_allowed_unix_ms: now,
                    version: 1,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let limits_path = faucet_limits_file();
            let _limits_lock = acquire_market_file_lock(&limits_path)?;
            let mut limits = load_faucet_limits(&limits_path);
            let window_ms = (window_seconds as u128) * 1000;
            let next_allowed_unix_ms;
            let mut allowed = true;

            {
                let entry = limits.entry(address.clone()).or_default();
                if entry.window_start_unix_ms == 0
                    || now.saturating_sub(entry.window_start_unix_ms) >= window_ms
                {
                    entry.window_start_unix_ms = now;
                    entry.count_in_window = 0;
                }
                if entry.count_in_window >= max_requests_in_window {
                    allowed = false;
                }
                next_allowed_unix_ms = entry.window_start_unix_ms.saturating_add(window_ms);
            }

            let account_path = account_state_file();
            let _account_lock = acquire_market_file_lock(&account_path)?;
            let mut accounts = load_account_state(&account_path);

            if !allowed {
                let acct = accounts.get(&address).cloned();
                let out = FaucetRequestResponse {
                    ok: false,
                    code: "RATE_LIMITED".into(),
                    message: "faucet rate limit exceeded".into(),
                    address,
                    requested_amount: amount,
                    granted_amount: 0,
                    balance: acct.as_ref().map(|a| a.balance),
                    nonce: acct.as_ref().map(|a| a.nonce),
                    window_seconds,
                    next_allowed_unix_ms,
                    version: 1,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let (new_balance, nonce) = {
                let acct = accounts.entry(address.clone()).or_insert(AccountState {
                    address: address.clone(),
                    balance: 0,
                    nonce: 0,
                });
                acct.balance = acct.balance.saturating_add(amount);
                (acct.balance, acct.nonce)
            };

            if let Some(entry) = limits.get_mut(&address) {
                entry.count_in_window = entry.count_in_window.saturating_add(1);
            }

            save_account_state(&account_path, &accounts)?;
            save_faucet_limits(&limits_path, &limits)?;

            let out = FaucetRequestResponse {
                ok: true,
                code: "OK".into(),
                message: "faucet granted".into(),
                address,
                requested_amount: amount,
                granted_amount: amount,
                balance: Some(new_balance),
                nonce: Some(nonce),
                window_seconds,
                next_allowed_unix_ms,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::SubmitMessage {
            channel,
            user_id,
            session_id,
            text,
            idempotency_key,
        } => {
            let path = ingress_file();
            let _lock = acquire_market_file_lock(&path)?;

            let mut records = load_ingress_records();
            if let Some(found) = records.iter().rev().find(|r| {
                is_same_submit_message_idempotency_scope(
                    r,
                    &channel,
                    &user_id,
                    &session_id,
                    &idempotency_key,
                )
            }) {
                println!("{}", serde_json::to_string_pretty(found)?);
                return Ok(());
            }

            // Quota gate applies to fresh ingress only. Existing idempotent records
            // must still replay successfully under tighter runtime limits.
            let max_bytes = submit_message_max_bytes() as usize;
            if text.len() > max_bytes {
                bail!(
                    "submit-message text exceeds {} bytes limit (got {})",
                    max_bytes,
                    text.len()
                );
            }

            validate_submit_message_metadata(&text)?;

            let ts = now_ms();
            let request_id = make_request_id(&channel, &user_id, &session_id, &idempotency_key, ts);
            let task_id = next_ingress_task_id(&records)?;
            let rec = MessageIngressRecord {
                request_id,
                task_id,
                channel,
                user_id,
                session_id,
                text,
                idempotency_key,
                status: RequestStatus::Open.as_str().into(),
                created_at_unix_ms: ts,
                assigned_worker: None,
                assigned_at_unix_ms: None,
                model_output: None,
                result_hash: None,
                verifier_status: None,
                resolution_code: None,
                commit_tx_hash: None,
                reveal_tx_hash: None,
            };

            records.push(rec.clone());
            save_ingress_records(&records)?;

            let out = MessageRequestQueryResponse {
                request_id: rec.request_id,
                task_id: rec.task_id,
                channel: rec.channel,
                user_id: rec.user_id,
                session_id: rec.session_id,
                text: rec.text,
                idempotency_key: rec.idempotency_key,
                status: rec.status,
                created_at_unix_ms: rec.created_at_unix_ms,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryRequest { request_id } => {
            let records = load_ingress_records();
            let Some(rec) = records
                .into_iter()
                .rev()
                .find(|r| r.request_id == request_id)
            else {
                bail!("request not found: {}", request_id);
            };
            let out = MessageRequestQueryResponse {
                request_id: rec.request_id,
                task_id: rec.task_id,
                channel: rec.channel,
                user_id: rec.user_id,
                session_id: rec.session_id,
                text: rec.text,
                idempotency_key: rec.idempotency_key,
                status: rec.status,
                created_at_unix_ms: rec.created_at_unix_ms,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::QueryRequestFull { request_id, limit } => {
            let limit = clamp_limit(
                "QueryRequestFull",
                limit,
                QUERY_FULL_LIMIT_DEFAULT,
                QUERY_FULL_LIMIT_MAX,
            );
            let records = load_ingress_records();
            let Some(rec) = records
                .into_iter()
                .rev()
                .find(|r| r.request_id == request_id)
            else {
                bail!("request not found: {}", request_id);
            };

            let node_events = load_node_events(NodeEventScanMode::Authoritative);
            let mut events = Vec::new();
            for e in filtered_node_events_for_task(rec.task_id, &node_events.events) {
                let Some(actor) = normalize_actor_or_signer(&e.actor) else {
                    continue;
                };
                let signer = e
                    .signer
                    .as_deref()
                    .and_then(normalize_actor_or_signer)
                    .or_else(|| Some(actor.clone()));
                let tx_hash = match e.event_type.as_str() {
                    "commit" => rec.commit_tx_hash.clone().or_else(|| e.tx_hash.clone()),
                    "reveal" => rec.reveal_tx_hash.clone().or_else(|| e.tx_hash.clone()),
                    _ => e.tx_hash.clone(),
                };
                let resolution_code = if e.event_type == "resolve" {
                    rec.resolution_code
                        .clone()
                        .or_else(|| e.resolution_code.clone())
                } else {
                    e.resolution_code.clone()
                };
                push_tail_limited(
                    &mut events,
                    EventQueryResponse {
                        event_type: e.event_type.clone(),
                        task_id: rec.task_id,
                        from_status: e.from_status.clone(),
                        to_status: e.to_status.clone(),
                        actor,
                        tx_id: e.tx_id,
                        block_height: e.block_height,
                        state_root: e.state_root.clone(),
                        ts_unix_ms: e.ts_unix_ms,
                        signer,
                        challenger: e.challenger.clone(),
                        tx_hash,
                        resolution_code,
                        treasury_delta: e.treasury_delta,
                        challenger_delta: e.challenger_delta,
                        bond_disposition: e.bond_disposition.clone(),
                        metering: e.metering.clone(),
                    },
                    limit,
                );
            }

            let out = RequestFullQueryResponse {
                request: MessageRequestQueryResponse {
                    request_id: rec.request_id,
                    task_id: rec.task_id,
                    channel: rec.channel,
                    user_id: rec.user_id,
                    session_id: rec.session_id,
                    text: rec.text,
                    idempotency_key: rec.idempotency_key,
                    status: rec.status,
                    created_at_unix_ms: rec.created_at_unix_ms,
                },
                verifier_status: rec.verifier_status,
                resolution_code: rec.resolution_code,
                result_hash: rec.result_hash,
                commit_tx_hash: rec.commit_tx_hash,
                reveal_tx_hash: rec.reveal_tx_hash,
                events,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::MarketCreateTask {
            creator,
            bounty,
            description,
        } => {
            let creator = creator.trim().to_string();

            if creator.is_empty() {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "task-creator-invalid",
                    message: "market task creator must be non-empty".to_string(),
                }));
            }
            if bounty == 0 {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "task-bounty-invalid",
                    message: "market task bounty must be greater than zero".to_string(),
                }));
            }

            let task = {
                let tasks_path = market_tasks_file();
                let _lock = acquire_market_file_lock(&tasks_path)?;
                let mut tasks = load_market_tasks();
                let task_id = 20_000 + tasks.len() as u64 + 1;
                let task = MarketTask {
                    task_id,
                    creator,
                    bounty,
                    description,
                    status: "open".into(),
                    created_at_unix_ms: now_ms(),
                };
                tasks.push(task.clone());
                save_market_tasks(&tasks)?;
                task
            };
            println!("{}", serde_json::to_string_pretty(&task)?);
        }
        Command::MarketSubmitBid {
            task_id,
            worker,
            price,
        } => {
            if worker.trim().is_empty() {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "worker-id-invalid",
                    message: format!("market bid worker must be non-empty for task {}", task_id),
                }));
            }
            if price == 0 {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "bid-price-invalid",
                    message: format!(
                        "market bid price must be greater than zero for task {}",
                        task_id
                    ),
                }));
            }
            let normalized_worker =
                normalize_market_worker_key(&worker).expect("worker checked non-empty");
            let bid = {
                // Acquire task lock first and keep it through bid persist so task
                // status checks and bid append are linearizable with match_task.
                let tasks_path = market_tasks_file();
                let _tasks_lock = acquire_market_file_lock(&tasks_path)?;
                let tasks = load_market_tasks();
                let Some(task) = tasks.iter().find(|t| t.task_id == task_id) else {
                    return Err(rpc_fail(RpcErrorResponse {
                        code: "task-not-found",
                        message: format!("market task not found: {}", task_id),
                    }));
                };
                if normalize_market_status_key(&task.status) != "open" {
                    return Err(rpc_fail(RpcErrorResponse {
                        code: "task-not-open",
                        message: format!("market task not in open status: {}", task.status),
                    }));
                }
                if price > task.bounty {
                    return Err(rpc_fail(RpcErrorResponse {
                        code: "bid-above-bounty",
                        message: format!(
                            "market bid price {} exceeds task bounty {} for task {}",
                            price, task.bounty, task_id
                        ),
                    }));
                }

                let bids_path = market_bids_file();
                let _bids_lock = acquire_market_file_lock(&bids_path)?;
                let mut bids = load_market_bids();
                if bids.iter().any(|b| {
                    b.task_id == task_id
                        && normalize_market_worker_key(&b.worker)
                            .map(|existing| existing == normalized_worker)
                            .unwrap_or(false)
                }) {
                    return Err(rpc_fail(RpcErrorResponse {
                        code: "duplicate-bid",
                        message: format!(
                            "worker {} already has a bid for task {}",
                            worker, task_id
                        ),
                    }));
                }
                let bid = MarketBid {
                    task_id,
                    worker,
                    price,
                    created_at_unix_ms: now_ms(),
                };
                bids.push(bid.clone());
                save_market_bids(&bids)?;
                bid
            };
            println!("{}", serde_json::to_string_pretty(&bid)?);
        }
        Command::MarketMatchTask { task_id } => {
            let tasks_path = market_tasks_file();
            let _tasks_lock = acquire_market_file_lock(&tasks_path)?;
            let bids_path = market_bids_file();
            let _bids_lock = acquire_market_file_lock(&bids_path)?;
            let mut tasks = load_market_tasks();
            let Some(task) = tasks.iter_mut().find(|t| t.task_id == task_id) else {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "task-not-found",
                    message: format!("market task not found: {}", task_id),
                }));
            };
            if normalize_market_status_key(&task.status) != "open" {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "task-not-open",
                    message: format!("market task not in open status: {}", task.status),
                }));
            }

            let bids = load_market_bids();
            let task_bids: Vec<&MarketBid> = bids.iter().filter(|b| b.task_id == task_id).collect();

            if task_bids.is_empty() {
                return Err(rpc_fail(RpcErrorResponse {
                    code: "no-bids",
                    message: format!("no bids found for task: {}", task_id),
                }));
            }

            let reputation = load_market_reputation();
            let score_cfg = market_score_config();
            let matched_bid_count = task_bids.len();
            let winner = task_bids
                .into_iter()
                .min_by_key(|b| {
                    let rep = normalize_market_worker_key(&b.worker)
                        .and_then(|k| reputation.get(&k).copied())
                        .unwrap_or(0);
                    let worker_key = market_worker_tie_break_key(&b.worker);
                    (
                        market_effective_score_with_config(b.price, rep, score_cfg),
                        b.price,
                        b.created_at_unix_ms,
                        worker_key,
                    )
                })
                .expect("non-empty bids");
            let winner_reputation_lookup_key = normalize_market_worker_key(&winner.worker);
            let winner_reputation_lookup_missing = winner_reputation_lookup_key
                .as_ref()
                .map(|k| !reputation.contains_key(k))
                .unwrap_or(true);
            let winner_reputation = winner_reputation_lookup_key
                .as_ref()
                .and_then(|k| reputation.get(k).copied())
                .unwrap_or(0);
            let breakdown = market_score_breakdown(winner.price, winner_reputation, score_cfg);
            let winner_reputation_effective = breakdown.effective_reputation;
            let base_score = breakdown.base_score;
            let reputation_weight = breakdown.reputation_reward;
            let penalty = breakdown.penalty;
            let reputation_score_delta = market_reputation_score_delta(&breakdown);
            let winner_score = breakdown.effective_score;

            task.status = "matched".into();
            save_market_tasks(&tasks)?;

            let out = serde_json::json!({
                "task_id": task_id,
                "winner": winner.worker,
                "price": winner.price,
                "status": "matched",
                "match_policy": "price_reputation_weighted",
                "matched_bid_count": matched_bid_count,
                "winner_reputation": winner_reputation,
                "winner_reputation_lookup_key": winner_reputation_lookup_key,
                "winner_reputation_lookup_missing": winner_reputation_lookup_missing,
                "winner_reputation_effective": winner_reputation_effective,
                "winner_reputation_clamp_limit": clamp_reputation_for_market(i64::MAX, score_cfg),
                "winner_reputation_clamped": winner_reputation != winner_reputation_effective,
                "score_floor_applied": breakdown.score_floor_applied,
                "price_weight_unit": score_cfg.price_weight,
                "base_score": base_score,
                "price_component": base_score,
                "reputation_weight_unit": score_cfg.reputation_weight,
                "reputation_weight": reputation_weight,
                "reputation_reward": reputation_weight,
                "penalty": penalty,
                "reputation_score_delta": reputation_score_delta,
                "final_score": winner_score,
                "effective_score": winner_score,
                "match_config": MarketScoreConfigOutput::from(score_cfg),
            });
            println!("{}", serde_json::to_string(&out)?);
        }
        Command::MarketReport {} => {
            let tasks = load_market_tasks();
            let bids = load_market_bids();
            let task_count = tasks.len();
            let open_task_count = tasks
                .iter()
                .filter(|t| normalize_market_status_key(&t.status) == "open")
                .count();
            let matched_task_count = tasks
                .iter()
                .filter(|t| normalize_market_status_key(&t.status) == "matched")
                .count();
            let bid_count = bids.len();
            let unmatched_task_count = task_count.saturating_sub(matched_task_count);

            let unique_bidder_count = bids
                .iter()
                .filter_map(|b| normalize_market_worker_key(&b.worker))
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let known_task_ids = tasks
                .iter()
                .map(|t| t.task_id)
                .collect::<std::collections::BTreeSet<_>>();
            let tasks_with_bids_count = bids
                .iter()
                .filter_map(|b| normalize_market_worker_key(&b.worker).map(|_| b.task_id))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|task_id| known_task_ids.contains(task_id))
                .count();
            let orphan_bid_count = bids
                .iter()
                .filter(|b| !known_task_ids.contains(&b.task_id))
                .count();
            let bid_coverage_rate = if task_count == 0 {
                0.0
            } else {
                tasks_with_bids_count as f64 / task_count as f64
            };
            let avg_bids_per_task = if task_count == 0 {
                0.0
            } else {
                bid_count as f64 / task_count as f64
            };
            let match_rate = if task_count == 0 {
                0.0
            } else {
                matched_task_count as f64 / task_count as f64
            };

            let out = MarketReport {
                task_count,
                open_task_count,
                matched_task_count,
                unmatched_task_count,
                bid_count,
                orphan_bid_count,
                unique_bidder_count,
                tasks_with_bids_count,
                bid_coverage_rate,
                avg_bids_per_task,
                match_rate,
                match_config: MarketScoreConfigOutput::from(market_score_config()),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::DispatchOpen { worker_id, limit } => {
            let limit = clamp_limit(
                "DispatchOpen",
                limit,
                DISPATCH_OPEN_LIMIT_DEFAULT,
                DISPATCH_OPEN_LIMIT_MAX,
            );
            let path = ingress_file();
            let _lock = acquire_market_file_lock(&path)?;
            let mut records = load_ingress_records();
            let mut assigned = Vec::<MessageRequestQueryResponse>::new();
            let ts = now_ms();
            let mut n = 0usize;
            for rec in records.iter_mut() {
                if n >= limit {
                    break;
                }
                if rec.status == RequestStatus::Open.as_str() {
                    rec.status = transition_request_status(&rec.status, RequestStatus::Assigned)?;
                    rec.assigned_worker = Some(worker_id.clone());
                    rec.assigned_at_unix_ms = Some(ts);
                    assigned.push(MessageRequestQueryResponse {
                        request_id: rec.request_id.clone(),
                        task_id: rec.task_id,
                        channel: rec.channel.clone(),
                        user_id: rec.user_id.clone(),
                        session_id: rec.session_id.clone(),
                        text: rec.text.clone(),
                        idempotency_key: rec.idempotency_key.clone(),
                        status: rec.status.clone(),
                        created_at_unix_ms: rec.created_at_unix_ms,
                    });
                    n += 1;
                }
            }
            save_ingress_records(&records)?;
            println!("{}", serde_json::to_string_pretty(&assigned)?);
        }
        Command::Serve { host, port } => {
            serve_health(&host, port)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard, OnceLock,
    };
    use trnm_types::CapabilityScope;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_env<'a>() -> MutexGuard<'a, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn unique_tmp_path(prefix: &str, ext: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "{}-{}-{}-{}.{}",
            prefix,
            std::process::id(),
            now_ms(),
            seq,
            ext
        ))
    }

    fn with_market_score_env(vars: &[(&str, &str)], f: impl FnOnce()) {
        let _guard = lock_env();
        let keys = [
            MARKET_PRICE_WEIGHT_ENV,
            MARKET_REPUTATION_WEIGHT_ENV,
            MARKET_REPUTATION_CLAMP_ENV,
        ];
        let prev: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();

        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }

        let run = catch_unwind(AssertUnwindSafe(f));

        for (k, v) in prev {
            match v {
                Some(val) => unsafe { std::env::set_var(&k, val) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }

        if let Err(panic) = run {
            std::panic::resume_unwind(panic);
        }
    }

    fn with_market_path_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = lock_env();
        let keys = [
            "TRNM_RPC_MARKET_TASKS_FILE",
            "TRNM_RPC_MARKET_BIDS_FILE",
            "TRNM_RPC_INGRESS_FILE",
            MARKET_REPUTATION_FILE_ENV,
            TASK_STATE_FILE_ENV,
        ];
        let prev: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();

        for (k, v) in vars {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }

        let run = catch_unwind(AssertUnwindSafe(f));

        for (k, v) in prev {
            match v {
                Some(val) => unsafe { std::env::set_var(&k, val) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }

        if let Err(panic) = run {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn resolve_capability_token_subject_or_token_strips_invisible_controls_before_lookup() {
        let mut registry = IdentityRegistry::default();
        registry
            .register_did(
                "did:org:lane-xi".to_string(),
                "org:lane-xi-admin".to_string(),
                10,
            )
            .expect("register did");
        let token_id = registry
            .issue_capability(
                "org:lane-xi-admin".to_string(),
                "did:org:lane-xi".to_string(),
                CapabilityScope::AuditRead,
                12,
                Some(120),
            )
            .expect("issue capability");

        assert_eq!(
            resolve_capability_token_subject_or_token(
                &registry,
                " \u{FEFF}did:org:lane-xi\u{200B} ",
            ),
            Some(token_id)
        );
    }

    #[test]
    fn resolve_capability_token_subject_or_token_rejects_noncanonical_subject_alias() {
        let mut registry = IdentityRegistry::default();
        registry
            .register_did(
                "did:org:lane-xi".to_string(),
                "org:lane-xi-admin".to_string(),
                10,
            )
            .expect("register did");
        let token_id = registry
            .issue_capability(
                "org:lane-xi-admin".to_string(),
                "did:org:lane-xi".to_string(),
                CapabilityScope::AuditRead,
                12,
                Some(120),
            )
            .expect("issue capability");

        assert_eq!(
            resolve_capability_token_subject_or_token(&registry, "did:org:lane-xi\n"),
            Some(token_id)
        );
        assert_eq!(
            resolve_capability_token_subject_or_token(&registry, "did:org:lane xi"),
            None,
            "non-canonical DID aliases must fail closed"
        );
    }

    #[test]
    fn resolve_capability_token_subject_or_token_fail_closed_without_structured_token() {
        let mut registry = IdentityRegistry::default();
        registry
            .register_did(
                "did:org:lane-xi".to_string(),
                "org:lane-xi-admin".to_string(),
                10,
            )
            .expect("register did");
        let token_id = registry
            .issue_capability(
                "org:lane-xi-admin".to_string(),
                "did:org:lane-xi".to_string(),
                CapabilityScope::AuditRead,
                12,
                Some(120),
            )
            .expect("issue capability");

        let mut raw = serde_json::to_value(&registry).expect("serialize registry");
        raw["capabilities"] = serde_json::json!({});
        if let Some(events) = raw["audit_trail"].as_array_mut() {
            if let Some(last) = events.last_mut() {
                last["note"] = serde_json::json!(format!("legacy-note token_id={token_id}"));
            }
        }
        let imported: IdentityRegistry =
            serde_json::from_value(raw).expect("deserialize mutated registry");

        assert_eq!(
            resolve_capability_token_subject_or_token(&imported, "did:org:lane-xi"),
            None,
            "subject lookup must fail-closed when structured token mapping is missing"
        );
    }

    #[test]
    fn parse_http_get_path_accepts_canonical_request_line() {
        assert_eq!(
            parse_http_get_path("GET /query-task/42?verbose=1 HTTP/1.1"),
            Some("/query-task/42")
        );
    }

    #[test]
    fn parse_http_get_path_rejects_fragment_suffixes_fail_closed() {
        assert_eq!(parse_http_get_path("GET /health#bridge HTTP/1.1"), None);
        assert_eq!(
            parse_http_get_path("GET /query-events/7?limit=5#tail HTTP/1.1"),
            None
        );
    }

    #[test]
    fn parse_http_get_path_rejects_percent_encoded_control_path_bytes_fail_closed() {
        assert_eq!(parse_http_get_path("GET /health%00check HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /health%7Fcheck HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /query-events/7%00 HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /query-events/7%7f HTTP/1.1"), None);
    }

    #[test]
    fn parse_query_events_limit_from_path_defaults_and_accepts_explicit_limit() {
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42").expect("default limit"),
            QUERY_EVENTS_LIMIT_DEFAULT
        );
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42?limit=7").expect("explicit limit"),
            7
        );
    }

    #[test]
    fn parse_query_events_limit_from_path_zero_uses_default_limit() {
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42?limit=0")
                .expect("zero limit should fall back to the bounded default"),
            QUERY_EVENTS_LIMIT_DEFAULT
        );
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_unrelated_query_keys() {
        for path in [
            "/query-events/42?foo=bar&limit=9",
            "/query-events/42?limit=9&foo=bar",
            "/query-events/42?foo=bar",
            "/query-events/42?limit=9&bar=baz",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("unrelated query keys must fail closed instead of being ignored");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_invalid_limit() {
        let err = parse_query_events_limit_from_path("/query-events/42?limit=bogus")
            .expect_err("invalid limit must fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid limit"));
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_uppercase_percent_encoded_query_delimiters() {
        for path in [
            "/query-events/42?limit=7%26limit=9",
            "/query-events/42?limit%3D9",
            "/query-events/42?limit=7%23tail",
            "/query-events/42?limit=7%0D%0Aextra",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("uppercase encoded delimiters must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_accepts_wrapped_numeric_limit() {
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42?limit=\"7\"")
                .expect("double-quoted numeric limit should parse"),
            7
        );
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42?limit='8'")
                .expect("single-quoted numeric limit should parse"),
            8
        );
        assert_eq!(
            parse_query_events_limit_from_path("/query-events/42?limit=  `9`  ")
                .expect("backtick-wrapped numeric limit should parse"),
            9
        );
    }

    #[test]
    fn parse_query_events_limit_from_path_clamps_to_hardcap() {
        assert_eq!(
            parse_query_events_limit_from_path(&format!(
                "/query-events/42?limit={}",
                QUERY_EVENTS_LIMIT_MAX + 99
            ))
            .expect("oversized limit should clamp to hardcap"),
            QUERY_EVENTS_LIMIT_MAX
        );
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_missing_limit_value() {
        let err = parse_query_events_limit_from_path("/query-events/42?limit")
            .expect_err("missing limit value must fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid limit"));
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_empty_query_suffix() {
        let err = parse_query_events_limit_from_path("/query-events/42?")
            .expect_err("empty query suffix must fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid limit"));
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_empty_limit_value() {
        let err = parse_query_events_limit_from_path("/query-events/42?limit=")
            .expect_err("empty limit value must fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid limit"));
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_encoded_query_smuggling() {
        for path in [
            "/query-events/42?limit=7%26limit=9",
            "/query-events/42?limit%3d7",
            "/query-events/42?foo=bar%26limit=9",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("encoded delimiters must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_malformed_unrelated_query_pairs() {
        for path in [
            "/query-events/42?foo&limit=7",
            "/query-events/42?foo=bar&baz",
            "/query-events/42?foo=bar&limit=7&qux",
            "/query-events/42??limit=7",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("malformed unrelated query pairs must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_percent_encoded_query_delimiters() {
        for path in [
            "/query-events/42?foo=bar%26limit=9",
            "/query-events/42?limit%3d9",
            "/query-events/42?limit=7%23tail",
            "/query-events/42?foo=bar%3flimit=9",
            "/query-events/42?foo=bar%0d%0alimit=9",
            "/query-events/42?limit=7%0d%0aextra",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("encoded query delimiters must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_raw_fragment_delimiters() {
        for path in [
            "/query-events/42?limit=7#tail",
            "/query-events/42?foo=bar#tail",
            "/query-events/42?foo=bar&limit=7#tail",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("raw fragment delimiters must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_percent_encoded_path_smuggling() {
        for path in [
            "/query-events%2f42?limit=7",
            "/query-events/..%2f42?limit=7",
            "/query-events/%2e%2e/42?limit=7",
            "/query-events/42%2ejson?limit=7",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("percent encoded path delimiters must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_events_limit_from_path_rejects_percent_encoded_control_path_bytes() {
        for path in [
            "/query-events/42%00?limit=7",
            "/query-events/42%7F?limit=7",
            "/query-events/%00/42?limit=7",
            "/query-events/%7f/42?limit=7",
        ] {
            let err = parse_query_events_limit_from_path(path)
                .expect_err("percent encoded control bytes in path must fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid limit"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_normalized_audit_events_query_from_path_defaults_and_filters() {
        let out =
            parse_query_normalized_audit_events_query_from_path("/query-normalized-audit-events")
                .expect("default should parse");
        assert_eq!(out.limit, QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT);
        assert!(out.source.is_none());
        assert!(out.event_type.is_none());
        assert!(out.cursor.is_none());

        let out = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events?source=trnm.task&eventType=trnm.task.commit&limit=3&cursor=2"
        )
        .expect("explicit query should parse");
        assert_eq!(out.source.as_deref(), Some("trnm.task"));
        assert_eq!(out.event_type.as_deref(), Some("trnm.task.commit"));
        assert_eq!(out.limit, 3);
        assert_eq!(out.cursor, Some(2));
    }

    #[test]
    fn parse_query_normalized_audit_events_query_from_path_rejects_unrelated_query_keys() {
        let err = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events?source=trnm.task&foo=bar",
        )
        .expect_err("unexpected keys should fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid query"));
    }

    #[test]
    fn parse_query_normalized_audit_events_query_from_path_rejects_invalid_cursor() {
        let err = parse_query_normalized_audit_events_query_from_path(
            "/query-normalized-audit-events?cursor=bad",
        )
        .expect_err("invalid cursor should fail closed");
        assert!(err.contains("400 Bad Request"));
        assert!(err.contains("invalid cursor"));
    }

    #[test]
    fn parse_query_normalized_audit_events_query_from_path_rejects_prefix_shadow_paths() {
        for path in [
            "/query-normalized-audit-events-shadow",
            "/query-normalized-audit-events-shadow?source=trnm.task",
            "/query-normalized-audit-events/extra",
            "/query-normalized-audit-events/extra?limit=2",
        ] {
            let err = parse_query_normalized_audit_events_query_from_path(path)
                .expect_err("prefix-shadow paths should fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid query"), "path={path} err={err}");
        }
    }

    #[test]
    fn parse_query_normalized_audit_events_query_from_path_rejects_percent_encoded_null_and_del_controls(
    ) {
        for path in [
            "/query-normalized-audit-events?source=trnm.task%00shadow",
            "/query-normalized-audit-events?eventType=trnm.task.commit%7ftrail",
            "/query-normalized-audit-events%00shadow?source=trnm.task",
            "/query-normalized-audit-events%7fshadow?source=trnm.task",
        ] {
            let err = parse_query_normalized_audit_events_query_from_path(path)
                .expect_err("encoded controls should fail closed");
            assert!(err.contains("400 Bad Request"), "path={path} err={err}");
            assert!(err.contains("invalid query"), "path={path} err={err}");
        }
    }

    #[test]
    fn query_normalized_audit_events_supports_pagination_and_event_filters() {
        let events = vec![
            NodeEventRecord {
                event_type: "accept".into(),
                task_id: 1,
                from_status: "Open".into(),
                to_status: "Assigned".into(),
                actor: "worker-a".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "s1".into(),
                ts_unix_ms: 100,
                signer: Some("worker-a".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: Some("accepted".into()),
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "commit".into(),
                task_id: 1,
                from_status: "Assigned".into(),
                to_status: "Committed".into(),
                actor: "worker-a".into(),
                tx_id: 2,
                block_height: 20,
                state_root: "s2".into(),
                ts_unix_ms: 200,
                signer: Some("worker-a".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
        ];

        let first = query_normalized_audit_events(
            &events,
            &[],
            &QueryNormalizedAuditEventsQuery {
                source: Some("trnm.task".into()),
                event_type: None,
                cursor: None,
                limit: 1,
            },
        );
        assert_eq!(first.total, Some(2));
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].event_type, "trnm.task.commit");
        assert_eq!(first.has_more, Some(true));
        assert_eq!(first.next_cursor.as_deref(), Some("1"));

        let second = query_normalized_audit_events(
            &events,
            &[],
            &QueryNormalizedAuditEventsQuery {
                source: Some("trnm.task".into()),
                event_type: Some("trnm.task.accept".into()),
                cursor: Some(0),
                limit: 10,
            },
        );
        assert_eq!(second.total, Some(1));
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].event_type, "trnm.task.accept");
        assert_eq!(second.has_more, Some(false));
    }

    #[test]
    fn query_normalized_audit_events_supports_adapter_source_filter() {
        let recs = vec![AdapterRecord {
            ts: 99,
            kind: "commit".into(),
            task_id: 5,
            worker: Some("worker-b".into()),
            result_hash: None,
            status: "accepted".into(),
            tx_hash: Some("0xfeed".into()),
        }];

        let out = query_normalized_audit_events(
            &[],
            &recs,
            &QueryNormalizedAuditEventsQuery {
                source: Some("trnm.adapter".into()),
                event_type: None,
                cursor: None,
                limit: 10,
            },
        );
        assert_eq!(out.total, Some(1));
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].source, "trnm.adapter");
        assert_eq!(out.events[0].event_type, "trnm.adapter.commit");
    }

    #[test]
    fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
        assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /health"), None);
        assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
    }

    #[test]
    fn parse_http_request_target_accepts_only_supported_http_versions() {
        assert_eq!(
            parse_http_request_target("GET /health HTTP/1.1"),
            Some(("GET", "/health"))
        );
        assert_eq!(
            parse_http_request_target("HEAD /readyz HTTP/1.0"),
            Some(("HEAD", "/readyz"))
        );
        assert_eq!(parse_http_request_target("GET /health HTTP/2"), None);
        assert_eq!(parse_http_request_target("GET /health HTTP/1.1junk"), None);
        assert_eq!(parse_http_request_target("GET /health http/1.1"), None);
    }

    #[test]
    fn health_probe_aliases_include_dash_prefixed_operator_paths() {
        assert!(is_health_probe_path("/-/health"));
        assert!(is_health_probe_path("/-/healthz/"));
        assert!(is_health_probe_path("/-/live"));
        assert!(is_health_probe_path("/-/readyz/"));
        assert!(is_health_probe_path("/-/status"));
        assert!(is_health_probe_path("/-/STATUSZ/"));
        assert!(!is_health_probe_path("/-/statuscheck"));
        assert!(!is_health_probe_path("/-/statusz//"));
        assert!(!is_health_probe_path("/-/readyz/extra"));
    }

    #[test]
    fn parse_http_request_target_preserves_query_string_for_dash_prefixed_health_aliases() {
        assert_eq!(
            parse_http_request_target("HEAD /-/statusz/?from=ops&probe=lb HTTP/1.1"),
            Some(("HEAD", "/-/statusz/?from=ops&probe=lb"))
        );
        assert_eq!(
            parse_http_get_path("GET /-/readyz?probe=lb HTTP/1.1"),
            Some("/-/readyz")
        );
    }

    #[test]
    fn mixed_case_status_health_alias_with_query_keeps_same_head_contract() {
        let request = parse_http_request_target("HEAD /-/STATUSZ/?from=ops&probe=lb HTTP/1.1")
            .expect("health alias request parses");
        let path = request.1.split('?').next().expect("path before query");

        assert_eq!(path, "/-/STATUSZ/");
        assert!(is_health_probe_path(path));

        let response = json_response_for_method(request.0, "200 OK", "{\"ok\":true}");

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 11\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.ends_with("{\"ok\":true}"));
    }

    #[test]
    fn parse_http_get_path_preserves_operator_trailing_slash_for_query_routes() {
        assert_eq!(
            parse_http_get_path("GET /query-task/42/ HTTP/1.1"),
            Some("/query-task/42/")
        );
        assert_eq!(
            parse_http_get_path("GET /query-events/7/?limit=5 HTTP/1.1"),
            Some("/query-events/7/")
        );
    }

    #[test]
    fn json_response_for_method_preserves_head_semantics_for_error_paths() {
        let not_found = json_response_for_method("HEAD", "404 Not Found", "{\"ok\":false}");
        assert!(not_found.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(not_found.ends_with("\r\n\r\n"));
        assert!(!not_found.ends_with("{\"ok\":false}"));
        assert!(not_found.contains("Content-Length: 12\r\n"));

        let bad_request = json_response_for_method(
            "HEAD",
            "400 Bad Request",
            "{\"ok\":false,\"code\":\"BAD_REQUEST\"}",
        );
        assert!(bad_request.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(bad_request.ends_with("\r\n\r\n"));
        assert!(!bad_request.ends_with("BAD_REQUEST\"}"));
    }

    #[test]
    fn parse_nonempty_path_suffix_rejects_empty_capability_subject() {
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/alice", "/query-capability-audit/"),
            Some("alice")
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice/",
                "/query-capability-audit/"
            ),
            Some("alice")
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit///", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice/extra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%2Fextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice%5cextra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix(
                "/query-capability-audit/alice\\extra",
                "/query-capability-audit/"
            ),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/.", "/query-capability-audit/"),
            None
        );
        assert_eq!(
            parse_nonempty_path_suffix("/query-capability-audit/..", "/query-capability-audit/"),
            None
        );
    }

    #[test]
    fn ambiguous_path_segment_encoding_rejects_encoded_slashes_case_insensitively() {
        assert!(has_ambiguous_path_segment_encoding("alice%2Fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%2fextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5Cextra"));
        assert!(has_ambiguous_path_segment_encoding("alice%5cextra"));
        assert!(!has_ambiguous_path_segment_encoding("did:trn:alice"));
    }

    #[test]
    fn read_http_request_head_times_out_on_partial_slowloris_client() {
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let client = thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect test listener");
            client
                .write_all(b"GET /health HTTP/1.1")
                .expect("write partial request");
            thread::sleep(Duration::from_millis(HEALTH_SOCKET_READ_TIMEOUT_MS + 250));
            let _ = client.shutdown(Shutdown::Both);
        });

        let (mut server_stream, _) = listener.accept().expect("accept test client");
        configure_health_stream(&server_stream).expect("configure timeouts");
        let err =
            read_http_request_head(&mut server_stream).expect_err("partial request must time out");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));

        client.join().expect("client thread join");
    }

    #[test]
    fn read_http_request_head_rejects_truncated_header_on_peer_close() {
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let client = thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect test listener");
            client
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost")
                .expect("write truncated request");
            client
                .shutdown(Shutdown::Write)
                .expect("shutdown write half after truncated request");
        });

        let (mut server_stream, _) = listener.accept().expect("accept test client");
        configure_health_stream(&server_stream).expect("configure timeouts");
        let err = read_http_request_head(&mut server_stream)
            .expect_err("truncated header must fail closed instead of being parsed");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        client.join().expect("client thread join");
    }

    #[test]
    fn read_http_request_head_rejects_oversized_header_without_terminator() {
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let oversized = vec![b'a'; HEALTH_REQUEST_HEADER_MAX_BYTES + 32];

        let client = thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect test listener");
            client
                .write_all(&oversized)
                .expect("write oversized request head without terminator");
            let _ = client.shutdown(Shutdown::Write);
        });

        let (mut server_stream, _) = listener.accept().expect("accept test client");
        configure_health_stream(&server_stream).expect("configure timeouts");
        let err = read_http_request_head(&mut server_stream)
            .expect_err("oversized unterminated header must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        client.join().expect("client thread join");
    }

    #[test]
    fn clamp_limit_enforces_max() {
        let got = clamp_limit(
            "QueryEvents",
            QUERY_EVENTS_LIMIT_MAX + 1,
            QUERY_EVENTS_LIMIT_DEFAULT,
            QUERY_EVENTS_LIMIT_MAX,
        );
        assert_eq!(got, QUERY_EVENTS_LIMIT_MAX);
    }

    #[test]
    fn clamp_limit_uses_default_when_zero() {
        let got = clamp_limit(
            "DispatchOpen",
            0,
            DISPATCH_OPEN_LIMIT_DEFAULT,
            DISPATCH_OPEN_LIMIT_MAX,
        );
        assert_eq!(got, DISPATCH_OPEN_LIMIT_DEFAULT);
    }

    #[test]
    fn clamp_limit_keeps_in_range_value() {
        let got = clamp_limit(
            "QueryRequestFull",
            17,
            QUERY_FULL_LIMIT_DEFAULT,
            QUERY_FULL_LIMIT_MAX,
        );
        assert_eq!(got, 17);
    }

    #[test]
    fn clamp_limit_clamps_oversized_default_when_zero_requested() {
        let got = clamp_limit("FeeBoundaryPrep", 0, 9, 4);
        assert_eq!(got, 4);
    }

    #[test]
    fn task_state_file_uses_trimmed_env_path() {
        with_market_path_env(
            &[(TASK_STATE_FILE_ENV, Some("  '/tmp/task-state.jsonl'  "))],
            || {
                assert_eq!(
                    task_state_file(),
                    Some(PathBuf::from("/tmp/task-state.jsonl"))
                );
            },
        );
    }

    #[test]
    fn push_tail_limited_keeps_only_most_recent_items_in_order() {
        let mut items = Vec::new();
        push_tail_limited(&mut items, 1, 3);
        push_tail_limited(&mut items, 2, 3);
        push_tail_limited(&mut items, 3, 3);
        push_tail_limited(&mut items, 4, 3);
        push_tail_limited(&mut items, 5, 3);
        assert_eq!(items, vec![3, 4, 5]);
    }

    #[test]
    fn push_tail_limited_fail_closes_when_limit_is_zero() {
        let mut items = vec![1, 2, 3];
        push_tail_limited(&mut items, 4, 0);
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn normalized_path_from_env_trims_shell_wrapped_quotes() {
        with_market_path_env(
            &[(
                "TRNM_RPC_MARKET_TASKS_FILE",
                Some("  \"/tmp/tasks.jsonl\"  "),
            )],
            || {
                assert_eq!(
                    normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                    Some(PathBuf::from("/tmp/tasks.jsonl"))
                );
            },
        );

        with_market_path_env(
            &[("TRNM_RPC_MARKET_TASKS_FILE", Some("'`/tmp/tasks.jsonl`'"))],
            || {
                assert_eq!(
                    normalized_path_from_env("TRNM_RPC_MARKET_TASKS_FILE"),
                    Some(PathBuf::from("/tmp/tasks.jsonl"))
                );
            },
        );
    }

    #[test]
    fn market_path_file_helpers_fallback_when_env_is_empty_after_trim() {
        with_market_path_env(
            &[
                ("TRNM_RPC_MARKET_TASKS_FILE", Some("   ")),
                ("TRNM_RPC_MARKET_BIDS_FILE", Some(" \"\" ")),
                ("TRNM_RPC_INGRESS_FILE", Some(" `   ` ")),
                (MARKET_REPUTATION_FILE_ENV, Some("  ''  ")),
            ],
            || {
                assert_eq!(
                    market_tasks_file(),
                    run_root().join("run/market/tasks.jsonl")
                );
                assert_eq!(market_bids_file(), run_root().join("run/market/bids.jsonl"));
                assert_eq!(
                    ingress_file(),
                    run_root().join("run/message-gateway/requests.jsonl")
                );
                assert_eq!(
                    market_reputation_file(),
                    run_root().join("run/market/reputation.json")
                );
            },
        );
    }

    #[test]
    fn rpc_state_paths_use_same_wrapped_env_and_empty_fallback_rules() {
        let _guard = lock_env();
        let keys = [
            "TRNM_RPC_ACCOUNTS_FILE",
            "TRNM_RPC_TX_FILE",
            "TRNM_RPC_FAUCET_LIMITS_FILE",
        ];
        let prev: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();

        unsafe {
            std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"/tmp/accounts.json\"  ");
            std::env::set_var("TRNM_RPC_TX_FILE", " '`/tmp/txs.json`' ");
            std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", "  /tmp/faucet_limits.json  ");
        }
        assert_eq!(account_state_file(), PathBuf::from("/tmp/accounts.json"));
        assert_eq!(tx_lifecycle_file(), PathBuf::from("/tmp/txs.json"));
        assert_eq!(
            faucet_limits_file(),
            PathBuf::from("/tmp/faucet_limits.json")
        );

        unsafe {
            std::env::set_var("TRNM_RPC_ACCOUNTS_FILE", "  \"\"  ");
            std::env::set_var("TRNM_RPC_TX_FILE", "  ''  ");
            std::env::set_var("TRNM_RPC_FAUCET_LIMITS_FILE", " `   ` ");
        }
        assert_eq!(
            account_state_file(),
            run_root().join("run/rpc/accounts.json")
        );
        assert_eq!(tx_lifecycle_file(), run_root().join("run/rpc/txs.json"));
        assert_eq!(
            faucet_limits_file(),
            run_root().join("run/rpc/faucet_limits.json")
        );

        for (k, v) in prev {
            match v {
                Some(val) => unsafe { std::env::set_var(&k, val) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    #[test]
    fn acquire_market_file_lock_cleans_stale_lock_file() {
        let _guard = lock_env();
        let prev = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();
        unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "1000") };

        let path = unique_tmp_path("market-lock", "jsonl");
        let lock_path = market_lock_path(&path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).expect("create lock dir");
        }
        fs::write(&lock_path, "stale").expect("seed stale lock");
        // Use extra margin above the 1000ms stale threshold to avoid filesystem
        // timestamp granularity edge-cases on slower CI runners.
        std::thread::sleep(Duration::from_millis(1200));

        {
            let _lock = acquire_market_file_lock(&path).expect("acquire cleans stale lock");
            assert!(lock_path.exists());
        }
        assert!(!lock_path.exists());

        match prev {
            Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
            None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
        }
    }

    #[test]
    fn acquire_market_file_lock_respects_timeout_when_lock_is_live() {
        let _guard = lock_env();
        let prev_timeout = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();
        let prev_stale = std::env::var("TRNM_RPC_MARKET_LOCK_STALE_MS").ok();

        unsafe {
            // Keep timeout short for deterministic gate speed.
            std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "100");
            // Treat existing lock as live (not stale) for this check.
            std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", "60000");
        }

        let path = unique_tmp_path("market-lock-timeout", "jsonl");
        let lock_path = market_lock_path(&path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).expect("create lock dir");
        }
        fs::write(&lock_path, "live").expect("seed live lock");

        let start = Instant::now();
        let err = match acquire_market_file_lock(&path) {
            Ok(_) => panic!("lock should time out while live lock exists"),
            Err(err) => err,
        };
        let elapsed = start.elapsed();
        let msg = err.to_string();

        assert!(msg.contains("timed out waiting for market file lock"));
        // Sleep interval is 10ms; allow scheduler jitter plus occasional heavily-loaded
        // CI runners while still catching hangs/regressions that overshoot timeout badly.
        let timeout_ms = market_lock_timeout_ms();
        let lower_bound_ms = timeout_ms.saturating_sub(10);
        let upper_bound_ms = timeout_ms.saturating_mul(8).saturating_add(200);
        assert!(elapsed >= Duration::from_millis(lower_bound_ms));
        assert!(elapsed < Duration::from_millis(upper_bound_ms));

        let _ = fs::remove_file(&lock_path);

        match prev_timeout {
            Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
            None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
        }
        match prev_stale {
            Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_STALE_MS", v) },
            None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_STALE_MS") },
        }
    }

    #[test]
    fn market_lock_timeout_ms_uses_wrapped_env_with_clamp_and_fallback() {
        let _guard = lock_env();
        let prev = std::env::var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS").ok();

        unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") };
        assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

        unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  `50`  ") };
        assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MIN);

        unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  \"70000\"  ") };
        assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_MAX);

        unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", "  not-a-number  ") };
        assert_eq!(market_lock_timeout_ms(), MARKET_LOCK_TIMEOUT_MS_DEFAULT);

        match prev {
            Some(v) => unsafe { std::env::set_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS", v) },
            None => unsafe { std::env::remove_var("TRNM_RPC_MARKET_LOCK_TIMEOUT_MS") },
        }
    }

    #[test]
    fn env_u64_with_min_accepts_wrapped_values_and_empty_fallback() {
        let _guard = lock_env();
        let key = "TRNM_RPC_TEST_ENV_U64_WITH_MIN";
        let prev = std::env::var(key).ok();

        unsafe { std::env::set_var(key, "  \"12\"  ") };
        assert_eq!(env_u64_with_min(key, 8, 1), 12);

        unsafe { std::env::set_var(key, "  ''  ") };
        assert_eq!(env_u64_with_min(key, 8, 1), 8);

        unsafe { std::env::set_var(key, "  `0`  ") };
        assert_eq!(env_u64_with_min(key, 8, 3), 3);

        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn normalize_market_status_key_collapses_hidden_and_control_separators() {
        assert_eq!(normalize_market_status_key(" matched\u{200b}"), "matched");
        assert_eq!(normalize_market_status_key("mat\u{00ad}ched"), "matched");
        assert_eq!(normalize_market_status_key("open\u{0007}"), "open");
        assert_eq!(
            normalize_market_status_key("\u{feff} matched \u{2060}"),
            "matched"
        );
    }

    #[test]
    fn market_reputation_loader_normalizes_worker_keys() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(&path, "{\" Worker-A \": 12, \"\": 99, \"WORKER-B\": -5}")
            .expect("write reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&12));
                assert_eq!(rep.get("worker-b"), Some(&-5));
                assert!(!rep.contains_key(" Worker-A "));
                assert!(!rep.contains_key(""));
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn stronger_market_reputation_signal_prefers_larger_absolute_value_and_negative_ties() {
        assert_eq!(stronger_market_reputation_signal(10, 200), 200);
        assert_eq!(stronger_market_reputation_signal(-7, -2), -7);
        assert_eq!(stronger_market_reputation_signal(12, -20), -20);
        assert_eq!(stronger_market_reputation_signal(20, -20), -20);
    }

    #[test]
    fn market_reputation_loader_uses_strongest_signal_when_aliases_collide() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_alias_collision_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            "{\"worker-a\": 10, \" Worker-A \": 200, \"WORKER-B\": -7, \" worker-b \": -2, \"worker-c\": 20, \" WORKER-C \": -20}",
        )
        .expect("write alias-collision reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&200));
                assert_eq!(rep.get("worker-b"), Some(&-7));
                assert_eq!(rep.get("worker-c"), Some(&-20));
                assert_eq!(rep.len(), 3);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_collapses_internal_whitespace_aliases() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_internal_ws_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            r#"{" Worker   A ": 10, "worker a": 25, "WORKER   B": -3}"#,
        )
        .expect("write internal-whitespace reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker a"), Some(&25));
                assert_eq!(rep.get("worker b"), Some(&-3));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_collapses_zero_width_aliases() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_zero_width_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            "{\"worker\\u200ba\": 9, \"worker a\": 31, \"worker\\u200db\": -2, \"worker\\u2060b\": 5}",
        )
        .expect("write zero-width reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker a"), Some(&31));
                assert_eq!(rep.get("worker b"), Some(&5));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_collapses_control_character_aliases() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_control_chars_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            "{\"worker\\u0007a\": 8, \"worker a\": 17, \"worker\\u000bb\": 4}",
        )
        .expect("write control-char reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker a"), Some(&17));
                assert_eq!(rep.get("worker b"), Some(&4));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_salvages_valid_entries_when_some_values_are_non_numeric() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_partial_invalid_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            r#"{"worker-a": 7, "worker-b": "bad", "worker-c": -3}"#,
        )
        .expect("write partial-invalid reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&7));
                assert_eq!(rep.get("worker-c"), Some(&-3));
                assert!(!rep.contains_key("worker-b"));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_accepts_integer_strings_and_skips_non_integer_strings() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_string_ints_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            r#"{"worker-a": " 11 ", "worker-b": "-4", "worker-c": "3.5", "worker-d": "oops"}"#,
        )
        .expect("write string-int reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&11));
                assert_eq!(rep.get("worker-b"), Some(&-4));
                assert!(!rep.contains_key("worker-c"));
                assert!(!rep.contains_key("worker-d"));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_accepts_integral_json_numbers_and_skips_fractional_numbers() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_float_ints_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            r#"{"worker-a": 11.0, "worker-b": -4.0, "worker-c": 3.5}"#,
        )
        .expect("write float-int reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&11));
                assert_eq!(rep.get("worker-b"), Some(&-4));
                assert!(!rep.contains_key("worker-c"));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_reputation_loader_accepts_stringified_i64_and_skips_non_integral_strings() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_stringified_i64_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            r#"{"worker-a": " 11 ", "worker-b": "-4", "worker-c": "3.5", "worker-d": "oops"}"#,
        )
        .expect("write string-int reputation fixture");

        with_market_path_env(
            &[(
                MARKET_REPUTATION_FILE_ENV,
                Some(path.to_string_lossy().as_ref()),
            )],
            || {
                let rep = load_market_reputation();
                assert_eq!(rep.get("worker-a"), Some(&11));
                assert_eq!(rep.get("worker-b"), Some(&-4));
                assert!(!rep.contains_key("worker-c"));
                assert!(!rep.contains_key("worker-d"));
                assert_eq!(rep.len(), 2);
            },
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn market_worker_tie_break_key_normalizes_case_and_whitespace() {
        assert_eq!(market_worker_tie_break_key(" Worker-A "), "worker-a");
        assert_eq!(market_worker_tie_break_key("worker-Z"), "worker-z");
    }

    #[test]
    fn market_effective_score_rewards_higher_reputation() {
        let low_rep = market_effective_score(100, 0);
        let high_rep = market_effective_score(100, 80);
        assert!(high_rep < low_rep);
    }

    #[test]
    fn market_effective_score_penalizes_negative_reputation() {
        let neutral = market_effective_score(100, 0);
        let penalized = market_effective_score(100, -50);
        assert!(penalized > neutral);
    }

    #[test]
    fn market_effective_score_applies_configured_reputation_weight() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "1000"),
                (MARKET_REPUTATION_WEIGHT_ENV, "10"),
                (MARKET_REPUTATION_CLAMP_ENV, "1000"),
            ],
            || {
                assert_eq!(market_effective_score(101, 20), 100_800);
            },
        );
    }

    #[test]
    fn market_score_config_uses_defaults_for_empty_wrapped_env_values() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, " '' "),
                (MARKET_REPUTATION_WEIGHT_ENV, " \"\" "),
                (MARKET_REPUTATION_CLAMP_ENV, " ` ` "),
            ],
            || {
                assert_eq!(market_effective_score(10, 5), 9_500);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_reputation_clamp_config_to_min_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "1000"),
                (MARKET_REPUTATION_WEIGHT_ENV, "100"),
                (MARKET_REPUTATION_CLAMP_ENV, "0"),
            ],
            || {
                assert_eq!(market_effective_score(101, 100_000), 100_900);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_reputation_clamp_config_to_max_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "1000"),
                (MARKET_REPUTATION_WEIGHT_ENV, "1"),
                (MARKET_REPUTATION_CLAMP_ENV, "9999999"),
            ],
            || {
                assert_eq!(market_effective_score(101, 2_000_000), 0);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_price_weight_config_to_min_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "0"),
                (MARKET_REPUTATION_WEIGHT_ENV, "1"),
                (MARKET_REPUTATION_CLAMP_ENV, "1000"),
            ],
            || {
                assert_eq!(market_effective_score(2, 0), 2);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_reputation_weight_config_to_min_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "1000"),
                (MARKET_REPUTATION_WEIGHT_ENV, "0"),
                (MARKET_REPUTATION_CLAMP_ENV, "1000"),
            ],
            || {
                assert_eq!(market_effective_score(2, 5), 1995);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_reputation_weight_config_to_max_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "1"),
                (MARKET_REPUTATION_WEIGHT_ENV, "999999999"),
                (MARKET_REPUTATION_CLAMP_ENV, "1000"),
            ],
            || {
                assert_eq!(market_effective_score(1, -2000), 1_000_000_001);
            },
        );
    }

    #[test]
    fn market_effective_score_clamps_price_weight_config_to_max_boundary() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "999999999"),
                (MARKET_REPUTATION_WEIGHT_ENV, "1"),
                (MARKET_REPUTATION_CLAMP_ENV, "1000"),
            ],
            || {
                assert_eq!(market_effective_score(2, 0), 2_000_000);
            },
        );
    }

    #[test]
    fn market_m2_policy_gate_guards_default_drift_to_min_boundaries() {
        with_market_score_env(
            &[
                (MARKET_PRICE_WEIGHT_ENV, "''"),
                (MARKET_REPUTATION_WEIGHT_ENV, "0"),
                (MARKET_REPUTATION_CLAMP_ENV, "0"),
            ],
            || {
                let cfg = market_score_config();
                assert_eq!(cfg.price_weight, MARKET_PRICE_WEIGHT_DEFAULT);
                assert_eq!(cfg.reputation_weight, MARKET_WEIGHT_MIN);
                assert_eq!(cfg.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
            },
        );
    }

    #[test]
    fn clamp_reputation_for_market_normalizes_negative_manual_clamp_to_fail_closed_minimum() {
        let cfg = MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: -10,
        };

        assert_eq!(clamp_reputation_for_market(250, cfg), 1);
        assert_eq!(clamp_reputation_for_market(-250, cfg), -1);
    }

    #[test]
    fn market_score_breakdown_normalizes_negative_manual_clamp_without_panic() {
        let breakdown = market_score_breakdown(
            50,
            250,
            MarketScoreConfig {
                price_weight: 3,
                reputation_weight: 7,
                reputation_clamp: -10,
            },
        );

        assert_eq!(breakdown.effective_reputation, 1);
        assert_eq!(breakdown.base_score, 150);
        assert_eq!(breakdown.reputation_reward, 7);
        assert_eq!(breakdown.effective_score, 143);
        assert_eq!(breakdown.penalty, 0);
        assert!(!breakdown.score_floor_applied);
    }

    #[test]
    fn market_score_config_output_normalizes_negative_manual_clamp_to_fail_closed_minimum() {
        let output = MarketScoreConfigOutput::from(MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: -10,
        });

        assert_eq!(output.price_weight, 3);
        assert_eq!(output.reputation_weight, 7);
        assert_eq!(output.reputation_clamp, 1);
    }

    #[test]
    fn normalize_tx_hash_lookup_tolerates_shell_wrapped_quotes() {
        assert_eq!(normalize_tx_hash_lookup("  \"0xAbC123\"  "), "0xabc123");
        assert_eq!(normalize_tx_hash_lookup(" '0xDeF456'\n"), "0xdef456");
        assert_eq!(normalize_tx_hash_lookup("'\"0xA1B2\"'"), "0xa1b2");
        assert_eq!(normalize_tx_hash_lookup(" `0xFf00` "), "0xff00");
        assert_eq!(normalize_tx_hash_lookup("`\"0xBEEF\"`"), "0xbeef");
    }

    #[test]
    fn normalize_tx_hash_lookup_tolerates_log_delimiter_wrapping() {
        assert_eq!(normalize_tx_hash_lookup("\"0xAbC123\","), "0xabc123");
        assert_eq!(normalize_tx_hash_lookup("(\"0xDeF456\")"), "0xdef456");
        assert_eq!(normalize_tx_hash_lookup("{'0xA1B2'};"), "0xa1b2");
        assert_eq!(normalize_tx_hash_lookup("[ `0xFf00` ]"), "0xff00");
        assert_eq!(normalize_tx_hash_lookup("tx=0xBEEF"), "tx=0xbeef");
    }

    #[test]
    fn normalize_tx_hash_lookup_accepts_common_key_value_forms() {
        assert_eq!(normalize_tx_hash_lookup("tx_hash=0xAbC123"), "0xabc123");
        assert_eq!(
            normalize_tx_hash_lookup("TxHash = \"0xDeF456\""),
            "0xdef456"
        );
        assert_eq!(normalize_tx_hash_lookup("hash= 0xA1B2"), "0xa1b2");
        assert_eq!(normalize_tx_hash_lookup("tx_hash:0xC0FFEE"), "0xc0ffee");
        assert_eq!(normalize_tx_hash_lookup("hash : `0xBEEF`"), "0xbeef");
        assert_eq!(normalize_tx_hash_lookup("tx-hash=0xCAFE"), "0xcafe");
        assert_eq!(normalize_tx_hash_lookup("tx_hash==0xFEED"), "0xfeed");
        assert_eq!(normalize_tx_hash_lookup("hash:: 0xBADA55"), "0xbada55");
        assert_eq!(normalize_tx_hash_lookup("tx hash = 0xF00D"), "0xf00d");
        assert_eq!(normalize_tx_hash_lookup("Tx.Hash: 0xFACE"), "0xface");
    }

    #[test]
    fn normalize_tx_hash_lookup_trims_sentence_period_after_hash_value() {
        assert_eq!(normalize_tx_hash_lookup("tx_hash=0xAbC123."), "0xabc123");
    }

    #[test]
    fn is_hex_like_tx_hash_accepts_only_0x_prefixed_hex() {
        assert!(is_hex_like_tx_hash("0xabc123"));
        assert!(is_hex_like_tx_hash("0xA1B2"));
        assert!(!is_hex_like_tx_hash("abc123"));
        assert!(!is_hex_like_tx_hash("0x"));
        assert!(!is_hex_like_tx_hash("0xzz99"));
        assert!(!is_hex_like_tx_hash("tx_hash=0xabc123"));
    }

    #[test]
    fn normalize_market_worker_key_strips_soft_hyphen_alias_spoofing() {
        let got = normalize_market_worker_key("Worker\u{00AD} A").expect("normalized");
        assert_eq!(got, "worker a");
        assert_eq!(
            normalize_market_worker_key("Worker A").expect("normalized"),
            got
        );
    }

    #[test]
    fn normalize_actor_or_signer_strips_controls_and_zero_width() {
        let got =
            normalize_actor_or_signer(" \u{200B}alice\u{2060}\u{0007} bob ").expect("normalized");
        assert_eq!(got, "alice bob");
        assert!(normalize_actor_or_signer("\u{200B}\u{2060}\u{0000}").is_none());
    }

    #[test]
    fn normalize_actor_or_signer_treats_controls_as_separators_not_concatenation() {
        let got = normalize_actor_or_signer("alice\u{0007}bob").expect("normalized");
        assert_eq!(got, "alice bob");
    }

    #[test]
    fn parse_u64_kv_value_tolerates_log_token_wrapping() {
        assert_eq!(parse_u64_kv_value("42"), Some(42));
        assert_eq!(parse_u64_kv_value("\"42\","), Some(42));
        assert_eq!(parse_u64_kv_value(" '42';"), Some(42));
        assert_eq!(parse_u64_kv_value("`42`"), Some(42));
        assert_eq!(parse_u64_kv_value("(42)"), Some(42));
        assert_eq!(parse_u64_kv_value("[42]"), Some(42));
        assert_eq!(parse_u64_kv_value("{42}"), Some(42));
        assert_eq!(parse_u64_kv_value("42."), Some(42));
        assert_eq!(parse_u64_kv_value("42:"), Some(42));
        assert_eq!(parse_u64_kv_value("bad42"), None);
        assert_eq!(parse_u64_kv_value("42ms"), None);
    }

    #[test]
    fn parse_u128_kv_value_tolerates_log_token_wrapping_without_suffix_false_positives() {
        assert_eq!(
            parse_u128_kv_value("1700000000123"),
            Some(1_700_000_000_123)
        );
        assert_eq!(
            parse_u128_kv_value("\"1700000000123\","),
            Some(1_700_000_000_123)
        );
        assert_eq!(
            parse_u128_kv_value("(1700000000123)"),
            Some(1_700_000_000_123)
        );
        assert_eq!(
            parse_u128_kv_value("1700000000123."),
            Some(1_700_000_000_123)
        );
        assert_eq!(parse_u128_kv_value("1700000000123ms"), None);
        assert_eq!(parse_u128_kv_value("ts=1700000000123"), None);
    }

    #[test]
    fn parse_i128_kv_value_tolerates_signed_wrapping_without_suffix_false_positives() {
        assert_eq!(parse_i128_kv_value("-42"), Some(-42));
        assert_eq!(parse_i128_kv_value("\"-42\","), Some(-42));
        assert_eq!(parse_i128_kv_value("(+7)"), Some(7));
        assert_eq!(parse_i128_kv_value("-42."), Some(-42));
        assert_eq!(parse_i128_kv_value("-42ms"), None);
        assert_eq!(parse_i128_kv_value("delta=-42"), None);
    }

    #[test]
    fn governance_state_merge_gate_keeps_emergency_pause_seeded_unpaused() {
        let st = governance_state();

        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("governance_state must seed emergency_pause at canonical key id");
        assert_eq!(
            pause.key_id, EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause canonical key_id drifted"
        );
        assert_eq!(pause.key, "emergency_pause");
        assert_eq!(pause.value, "false");
        assert_eq!(pause.version, 1);
        assert!(
            !st.is_emergency_paused(),
            "bootstrap governance_state must start unpaused"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "bootstrap governance_state must not leave emergency_pause queued"
        );
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_remains_immediate() {
        let mut st = governance_state();

        let pause = st
            .set_gov_param(
                9_001,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true".into(),
            )
            .expect("pause update must succeed");
        assert!(matches!(
            pause,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(
            st.is_emergency_paused(),
            "pause=true must apply immediately"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "pause=true must not enqueue timelock state"
        );
        let paused_param = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("paused emergency_pause param must remain readable");
        assert_eq!(paused_param.value, "true");
        assert_eq!(
            paused_param.version, 2,
            "pause=true immediate apply must bump emergency_pause version"
        );

        let unpause = st
            .set_gov_param(
                9_002,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "false".into(),
            )
            .expect("unpause update must succeed");
        assert!(matches!(
            unpause,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(
            !st.is_emergency_paused(),
            "pause=false must apply immediately"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "pause=false must not enqueue timelock state"
        );
        let unpaused_param = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("unpaused emergency_pause param must remain readable");
        assert_eq!(unpaused_param.value, "false");
        assert_eq!(
            unpaused_param.version, 3,
            "pause=false immediate apply must bump emergency_pause version"
        );
    }

    #[test]
    fn governance_state_merge_gate_rejects_non_canonical_emergency_pause_key_id() {
        let mut st = governance_state();

        let err = st
            .set_gov_param(9_003, 8_000, "emergency_pause".into(), "true".into())
            .expect_err("non-canonical emergency_pause key id must be rejected");
        assert!(err.contains("governance key id mismatch"));

        // Reject path must be side-effect free on pause state and pending queues.
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.key_id, EMERGENCY_PAUSE_KEY_ID);
        assert_eq!(pause.version, 1);
        assert_eq!(pause.value, "false");
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_replace_action_stays_immediate() {
        let mut st = governance_state();

        let paused = st
            .set_gov_param_with_action(
                9_004,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true".into(),
                trnm_state::GovPendingUpdateAction::Replace,
            )
            .expect("pause replace action must still succeed for non-sensitive key");
        assert!(matches!(
            paused,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(st.is_emergency_paused());
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "replace action must not queue emergency_pause timelock"
        );

        let unpaused = st
            .set_gov_param_with_action(
                9_005,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "false".into(),
                trnm_state::GovPendingUpdateAction::Replace,
            )
            .expect("unpause replace action must still succeed for non-sensitive key");
        assert!(matches!(
            unpaused,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_enforce_action_stays_immediate() {
        let mut st = governance_state();

        let paused = st
            .set_gov_param_with_action(
                9_006,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true".into(),
                trnm_state::GovPendingUpdateAction::Enforce,
            )
            .expect("pause enforce action must still succeed for non-sensitive key");
        assert!(matches!(
            paused,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(st.is_emergency_paused());
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "enforce action must not queue emergency_pause timelock"
        );

        let unpaused = st
            .set_gov_param_with_action(
                9_007,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "false".into(),
                trnm_state::GovPendingUpdateAction::Enforce,
            )
            .expect("unpause enforce action must still succeed for non-sensitive key");
        assert!(matches!(
            unpaused,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
        assert!(!st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_cancel_rejected_without_side_effects() {
        let mut st = governance_state();

        st.set_gov_param(
            9_006,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause=true must apply immediately");
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        let err = st
            .set_gov_param_with_action(
                9_007,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true".into(),
                trnm_state::GovPendingUpdateAction::Cancel,
            )
            .expect_err("cancel must remain unsupported for non-sensitive emergency_pause");
        assert!(
            err.contains("cancel not supported for non-sensitive key"),
            "{err}"
        );

        assert!(
            st.is_emergency_paused(),
            "cancel reject path must not flip emergency_pause"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "cancel reject path must not create pending timelock state"
        );
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_cancel_wrong_key_id_rejected_without_mutation() {
        let mut st = governance_state();

        st.set_gov_param(
            9_007,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause=true must apply immediately");
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());

        let err = st
            .set_gov_param_with_action(
                9_008,
                8_000,
                "emergency_pause".into(),
                "true".into(),
                trnm_state::GovPendingUpdateAction::Cancel,
            )
            .expect_err("cancel with non-canonical key id must be rejected");
        assert!(err.contains("governance key id mismatch"), "{err}");

        // Reject path must be side-effect free.
        assert!(st.is_emergency_paused());
        assert!(st.pending_gov_update("emergency_pause").is_none());
        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.value, "true");
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_rejects_invalid_bool_without_side_effects() {
        let mut st = governance_state();

        let err = st
            .set_gov_param(
                9_008,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "TRUE".into(),
            )
            .expect_err("invalid bool literal must be rejected");
        assert!(
            err.contains("expected strict bool 'true' or 'false'"),
            "{err}"
        );

        assert!(
            !st.is_emergency_paused(),
            "invalid bool reject path must keep emergency_pause unpaused"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "invalid bool reject path must not create pending timelock state"
        );

        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.value, "false");
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_replace_rejects_invalid_bool_without_side_effects(
    ) {
        let mut st = governance_state();

        let err = st
            .set_gov_param_with_action(
                9_009,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "TRUE".into(),
                trnm_state::GovPendingUpdateAction::Replace,
            )
            .expect_err("replace action must reject non-strict bool literals");
        assert!(
            err.contains("expected strict bool 'true' or 'false'"),
            "{err}"
        );

        assert!(
            !st.is_emergency_paused(),
            "replace invalid-bool reject path must keep emergency_pause unpaused"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "replace invalid-bool reject path must not create pending timelock state"
        );

        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.value, "false");
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_rejects_whitespace_bool_without_side_effects() {
        let mut st = governance_state();

        let err = st
            .set_gov_param(
                9_011,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "true ".into(),
            )
            .expect_err("bool literal with trailing whitespace must be rejected");
        assert!(
            err.contains("expected strict bool 'true' or 'false'"),
            "{err}"
        );

        assert!(
            !st.is_emergency_paused(),
            "whitespace bool reject path must keep emergency_pause unpaused"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "whitespace bool reject path must not create pending timelock state"
        );

        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.value, "false");
    }

    #[test]
    fn governance_state_merge_gate_emergency_pause_cancel_skips_value_parse_but_stays_side_effect_free(
    ) {
        let mut st = governance_state();

        let err = st
            .set_gov_param_with_action(
                9_010,
                EMERGENCY_PAUSE_KEY_ID,
                "emergency_pause".into(),
                "NOT_BOOL".into(),
                trnm_state::GovPendingUpdateAction::Cancel,
            )
            .expect_err("cancel must remain unsupported for non-sensitive emergency_pause");
        assert!(
            err.contains("cancel not supported for non-sensitive key"),
            "{err}"
        );
        assert!(
            !err.contains("invalid governance value"),
            "cancel path must skip strict bool parsing"
        );

        assert!(
            !st.is_emergency_paused(),
            "cancel reject path with invalid value must keep emergency_pause unpaused"
        );
        assert!(
            st.pending_gov_update("emergency_pause").is_none(),
            "cancel reject path must not create pending timelock state"
        );

        let pause = st
            .get_param(EMERGENCY_PAUSE_KEY_ID)
            .expect("canonical emergency_pause param must remain readable");
        assert_eq!(pause.value, "false");
    }

    #[test]
    fn summarize_challenge_treasury_tracks_balances_and_forfeits() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 1001,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "challenger-a".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "s1".into(),
                ts_unix_ms: 100,
                signer: Some("challenger-a".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: Some("0x01".into()),
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-10),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 1001,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "validator".into(),
                tx_id: 2,
                block_height: 11,
                state_root: "s2".into(),
                ts_unix_ms: 120,
                signer: Some("validator".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: Some("0x02".into()),
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 1002,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "challenger-b".into(),
                tx_id: 3,
                block_height: 12,
                state_root: "s3".into(),
                ts_unix_ms: 140,
                signer: Some("challenger-b".into()),
                challenger: Some("challenger-b".into()),
                tx_hash: Some("0x03".into()),
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-7),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 1002,
                from_status: "Challenged".into(),
                to_status: "Slashed".into(),
                actor: "validator".into(),
                tx_id: 4,
                block_height: 13,
                state_root: "s4".into(),
                ts_unix_ms: 160,
                signer: Some("validator".into()),
                challenger: Some("challenger-b".into()),
                tx_hash: Some("0x04".into()),
                resolution_code: Some("slashed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(7),
                bond_disposition: Some("refunded".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            None,
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 10);
        assert_eq!(out.cumulative_forfeited, 10);
        assert_eq!(out.events_total, 4);
        assert_eq!(out.events.len(), 4);
        assert_eq!(out.events[1].forfeits_delta, 10);
        assert_eq!(out.events[3].forfeits_delta, 0);
    }

    #[test]
    fn summarize_challenge_treasury_timeout_refund_is_non_forfeit() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 2001,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "challenger-a".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "s1".into(),
                ts_unix_ms: 100,
                signer: Some("challenger-a".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: Some("0x01".into()),
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-10),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "timeout".into(),
                task_id: 2001,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "system".into(),
                tx_id: 2,
                block_height: 11,
                state_root: "s2".into(),
                ts_unix_ms: 120,
                signer: Some("system".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: Some("0x02".into()),
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(10),
                bond_disposition: Some("refunded".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((50, 200, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 0);
        assert_eq!(out.cumulative_forfeited, 0);
        assert_eq!(out.events_total, 2);
        assert_eq!(out.events[1].forfeits_delta, 0);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 1);
        assert_eq!(summary.refunded, 1);
        assert_eq!(summary.forfeited, 0);
        assert_eq!(summary.unresolved, 0);
    }

    #[test]
    fn summarize_challenge_treasury_limit_keeps_recent() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 1,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c1".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "a".into(),
                ts_unix_ms: 1,
                signer: None,
                challenger: Some("c1".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-3),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 2,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c2".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "b".into(),
                ts_unix_ms: 2,
                signer: None,
                challenger: Some("c2".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-4),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
        ];

        let out =
            summarize_challenge_treasury(&events, 1, None, NodeEventScanMode::Authoritative, false);
        assert_eq!(out.events_total, 2);
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].task_id, 2);
        assert_eq!(out.current_escrow_balance, 7);
        assert!(out.daily_summary.is_none());
        assert!(out.window.is_none());
    }

    #[test]
    fn summarize_challenge_treasury_window_daily_summary_counts() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 11,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c11".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "a".into(),
                ts_unix_ms: 1_000,
                signer: None,
                challenger: Some("c11".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-5),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 11,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "v".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "b".into(),
                ts_unix_ms: 2_000,
                signer: None,
                challenger: Some("c11".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("refunded".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 12,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c12".into(),
                tx_id: 3,
                block_height: 3,
                state_root: "c".into(),
                ts_unix_ms: 3_000,
                signer: None,
                challenger: Some("c12".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-8),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 99,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "v".into(),
                tx_id: 4,
                block_height: 4,
                state_root: "d".into(),
                ts_unix_ms: 4_000,
                signer: None,
                challenger: Some("c99".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 3_500, "custom".to_string())),
            NodeEventScanMode::Authoritative,
            false,
        );

        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 2);
        assert_eq!(summary.refunded, 1);
        assert_eq!(summary.forfeited, 0);
        assert_eq!(summary.unresolved, 1);
        assert_eq!(out.window.expect("window expected").mode, "custom");
    }

    #[test]
    fn summarize_challenge_treasury_ignores_invalid_challenge_delta_sign() {
        let events = vec![NodeEventRecord {
            event_type: "challenge".into(),
            task_id: 77,
            from_status: "Revealed".into(),
            to_status: "Challenged".into(),
            actor: "c77".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "a".into(),
            ts_unix_ms: 1_000,
            signer: None,
            challenger: Some("c77".into()),
            tx_hash: None,
            resolution_code: None,
            treasury_delta: Some(0),
            challenger_delta: Some(10),
            bond_disposition: Some("posted".into()),
            metering: None,
        }];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 1_500, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 0);
        assert_eq!(out.cumulative_forfeited, 0);
        assert_eq!(out.events[0].bond_amount, 0);
        assert_eq!(out.events[0].escrow_delta, 0);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 0);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(out.anomaly_count, 1);
        assert_eq!(out.anomalies[0].code, "invalid_challenge_delta_sign");
    }

    #[test]
    fn summarize_challenge_treasury_does_not_count_or_move_missing_posted_bond() {
        let events = vec![NodeEventRecord {
            event_type: "resolve".into(),
            task_id: 88,
            from_status: "Challenged".into(),
            to_status: "Completed".into(),
            actor: "v".into(),
            tx_id: 2,
            block_height: 2,
            state_root: "b".into(),
            ts_unix_ms: 2_000,
            signer: None,
            challenger: Some("c88".into()),
            tx_hash: None,
            resolution_code: Some("completed".into()),
            treasury_delta: Some(0),
            challenger_delta: Some(0),
            bond_disposition: Some("forfeited".into()),
            metering: None,
        }];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 3_000, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 0);
        assert_eq!(out.cumulative_forfeited, 0);
        assert_eq!(out.events[0].bond_amount, 0);
        assert_eq!(out.events[0].escrow_delta, 0);
        assert_eq!(out.events[0].forfeits_delta, 0);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.forfeited, 0);
        assert_eq!(summary.refunded, 0);
        assert_eq!(out.anomaly_count, 1);
        assert_eq!(out.anomalies[0].code, "resolve_without_posted_bond");
    }

    #[test]
    fn summarize_challenge_treasury_ignores_duplicate_open_challenge_for_same_task() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 55,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c55".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "a".into(),
                ts_unix_ms: 1_000,
                signer: None,
                challenger: Some("c55".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-9),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 55,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c55".into(),
                tx_id: 2,
                block_height: 11,
                state_root: "b".into(),
                ts_unix_ms: 2_000,
                signer: None,
                challenger: Some("c55".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-4),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 55,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "validator".into(),
                tx_id: 3,
                block_height: 12,
                state_root: "c".into(),
                ts_unix_ms: 3_000,
                signer: None,
                challenger: Some("c55".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 3_500, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 9);
        assert_eq!(out.cumulative_forfeited, 9);
        assert_eq!(out.events[0].bond_amount, 9);
        assert_eq!(out.events[1].bond_amount, 0);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 1);
        assert_eq!(summary.forfeited, 1);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(out.anomaly_count, 1);
        assert_eq!(out.anomalies[0].code, "duplicate_open_challenge");
    }

    #[test]
    fn summarize_challenge_treasury_duplicate_resolve_replay_marks_replay_anomaly() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 66,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c66".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "a".into(),
                ts_unix_ms: 1_000,
                signer: None,
                challenger: Some("c66".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-6),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 66,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "validator".into(),
                tx_id: 2,
                block_height: 11,
                state_root: "b".into(),
                ts_unix_ms: 2_000,
                signer: None,
                challenger: Some("c66".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 66,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "validator".into(),
                tx_id: 2,
                block_height: 12,
                state_root: "c".into(),
                ts_unix_ms: 2_100,
                signer: None,
                challenger: Some("c66".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 3_000, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 6);
        assert_eq!(out.cumulative_forfeited, 6);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 1);
        assert_eq!(summary.forfeited, 1);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(out.anomaly_count, 1);
        assert_eq!(out.anomalies[0].code, "duplicate_event_replay");
    }

    #[test]
    fn summarize_challenge_treasury_ignores_non_terminal_disposition_without_clearing_posted_bond()
    {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 77,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "c77".into(),
                tx_id: 1,
                block_height: 10,
                state_root: "a".into(),
                ts_unix_ms: 1_000,
                signer: None,
                challenger: Some("c77".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-8),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 77,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "validator".into(),
                tx_id: 2,
                block_height: 11,
                state_root: "b".into(),
                ts_unix_ms: 2_000,
                signer: None,
                challenger: Some("c77".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 77,
                from_status: "Challenged".into(),
                to_status: "Slashed".into(),
                actor: "validator".into(),
                tx_id: 3,
                block_height: 12,
                state_root: "c".into(),
                ts_unix_ms: 3_000,
                signer: None,
                challenger: Some("c77".into()),
                tx_hash: None,
                resolution_code: Some("slashed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
        ];

        let out = summarize_challenge_treasury(
            &events,
            10,
            Some((500, 3_500, "custom".into())),
            NodeEventScanMode::Authoritative,
            false,
        );
        assert_eq!(out.current_escrow_balance, 0);
        assert_eq!(out.current_forfeits_balance, 8);
        assert_eq!(out.cumulative_forfeited, 8);
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[1].bond_amount, 8);
        assert_eq!(out.events[1].escrow_delta, -8);
        assert_eq!(out.events[1].forfeits_delta, 8);
        let summary = out.daily_summary.expect("summary expected");
        assert_eq!(summary.posted, 1);
        assert_eq!(summary.forfeited, 1);
        assert_eq!(summary.unresolved, 0);
        assert_eq!(out.anomaly_count, 0);
    }

    #[test]
    fn resolve_ops_window_custom_validation() {
        assert!(resolve_ops_window(Some(OpsWindowArg::Custom), None, Some(1), 10).is_err());
        assert!(resolve_ops_window(Some(OpsWindowArg::Custom), Some(2), Some(1), 10).is_err());
        assert!(resolve_ops_window(
            Some(OpsWindowArg::Custom),
            Some(0),
            Some(OPS_WINDOW_CUSTOM_MAX_MS + 1),
            10
        )
        .is_err());

        let got = resolve_ops_window(Some(OpsWindowArg::H24), None, None, 1_000).unwrap();
        let (from, to, mode) = got.expect("window expected");
        assert_eq!(to, 1_000);
        assert_eq!(mode, "24h");
        assert!(from <= to);
    }

    #[test]
    fn make_request_id_is_deterministic_and_separator_sensitive() {
        let a = make_request_id("telegram", "u1", "s1", "idem-1", 123);
        let b = make_request_id("telegram", "u1", "s1", "idem-1", 123);
        let c = make_request_id("telegram|u1", "s1", "idem-1", "", 123);

        assert_eq!(a, b, "same tuple must hash to a stable request id");
        assert_ne!(a, c, "field separators must keep scopes unambiguous");
        assert!(a.starts_with("req_"));
        assert_eq!(a.len(), 20, "req_ + 16 hex chars");
    }

    #[test]
    fn submit_message_idempotency_scope_requires_channel_user_session_and_key_match() {
        let rec = MessageIngressRecord {
            request_id: "req_1".into(),
            task_id: 42,
            channel: "telegram".into(),
            user_id: "u1".into(),
            session_id: "s1".into(),
            text: "hi".into(),
            idempotency_key: "idem-1".into(),
            status: RequestStatus::Open.as_str().into(),
            created_at_unix_ms: 1,
            assigned_worker: None,
            assigned_at_unix_ms: None,
            model_output: None,
            result_hash: None,
            verifier_status: None,
            resolution_code: None,
            commit_tx_hash: None,
            reveal_tx_hash: None,
        };

        assert!(is_same_submit_message_idempotency_scope(
            &rec, "telegram", "u1", "s1", "idem-1"
        ));
        assert!(!is_same_submit_message_idempotency_scope(
            &rec, "discord", "u1", "s1", "idem-1"
        ));
        assert!(!is_same_submit_message_idempotency_scope(
            &rec, "telegram", "u2", "s1", "idem-1"
        ));
        assert!(!is_same_submit_message_idempotency_scope(
            &rec, "telegram", "u1", "s2", "idem-1"
        ));
        assert!(!is_same_submit_message_idempotency_scope(
            &rec, "telegram", "u1", "s1", "idem-2"
        ));
    }

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
    fn query_task_from_node_events_uses_latest_status_and_worker() {
        let events = vec![
            NodeEventRecord {
                event_type: "accept".into(),
                task_id: 42,
                from_status: "Open".into(),
                to_status: "Assigned".into(),
                actor: "worker-a".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "s1".into(),
                ts_unix_ms: 1,
                signer: None,
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "commit".into(),
                task_id: 42,
                from_status: "Assigned".into(),
                to_status: "Committed".into(),
                actor: "worker-b".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "s2".into(),
                ts_unix_ms: 2,
                signer: None,
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 42,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "challenger".into(),
                tx_id: 3,
                block_height: 3,
                state_root: "s3".into(),
                ts_unix_ms: 3,
                signer: None,
                challenger: Some("challenger".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
        ];

        let out = query_task_from_node_events(42, &events).expect("task expected");
        assert_eq!(out.version, 3);
        assert_eq!(out.status, TaskStatus::Challenged);
        assert_eq!(out.worker.as_deref(), Some("worker-b"));
    }

    #[test]
    fn query_task_from_state_snapshot_computes_metering_derived_block() {
        let tasks = vec![TaskObject {
            task_id: 77,
            creator: "alice".into(),
            bounty: 777,
            status: TaskStatus::Completed,
            proof_type: trnm_types::ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: None,
                task_type: None,
                input_hash: None,
                model: None,
                provenance: None,
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "llm_inference".into(),
                    metering_schema: "llm_token_meter_v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "deadbeef".into(),
                    prompt_tokens: 128,
                    generated_tokens: 32,
                    decode_steps: 32,
                    kv_bytes_moved: 4096,
                    normalized_work_units: 192,
                    prompt_token_weight: 1,
                    generated_token_weight: 1,
                    decode_step_weight: 1,
                    kv_byte_weight: 0,
                    min_accept_work_units: 100,
                    challenge_success_bounty_base: 1,
                    challenge_success_bounty_per_work_unit_num: 1,
                    challenge_success_bounty_per_work_unit_den: 192,
                    worker_completion_bonus_per_work_unit_num: 1,
                    worker_completion_bonus_per_work_unit_den: 256,
                    worker_slash_rebate_per_work_unit_num: 1,
                    worker_slash_rebate_per_work_unit_den: 384,
                }),
            }),
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 9,
        }];
        let out = query_task_from_state_snapshot(77, &tasks).expect("task expected");
        let metering = out.metering.expect("metering expected");
        assert_eq!(metering.derived.path, "Completed");
        assert!(metering.derived.accept_floor_pass);
        assert_eq!(metering.derived.challenge_metered_bonus, 1);
        assert_eq!(metering.derived.challenge_bonus_total, 2);
        assert_eq!(metering.derived.worker_completion_bonus, 1);
        assert_eq!(metering.derived.worker_slash_rebate, 1);
    }

    #[test]
    fn query_task_from_state_snapshot_exposes_metering_audit_fields() {
        let tasks = vec![TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 777,
            status: TaskStatus::Revealed,
            proof_type: trnm_types::ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: None,
                task_type: None,
                input_hash: None,
                model: None,
                provenance: None,
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "llm_inference".into(),
                    metering_schema: "llm_token_meter_v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "deadbeef".into(),
                    prompt_tokens: 128,
                    generated_tokens: 32,
                    decode_steps: 32,
                    kv_bytes_moved: 4096,
                    normalized_work_units: 192,
                    prompt_token_weight: 1,
                    generated_token_weight: 1,
                    decode_step_weight: 1,
                    kv_byte_weight: 0,
                    min_accept_work_units: 100,
                    challenge_success_bounty_base: 1,
                    challenge_success_bounty_per_work_unit_num: 1,
                    challenge_success_bounty_per_work_unit_den: 192,
                    worker_completion_bonus_per_work_unit_num: 1,
                    worker_completion_bonus_per_work_unit_den: 256,
                    worker_slash_rebate_per_work_unit_num: 1,
                    worker_slash_rebate_per_work_unit_den: 384,
                }),
            }),
            worker: Some("worker-a".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 9,
        }];

        let out = query_task_from_state_snapshot(42, &tasks).expect("task expected");
        let expected_result_hash = hex::encode([0xabu8; 32]);
        assert_eq!(out.bounty, 777);
        assert_eq!(
            out.result_hash_hex.as_deref(),
            Some(expected_result_hash.as_str())
        );
        let metering = out.metering.expect("metering expected");
        assert_eq!(metering.normalized_work_units, 192);
        assert_eq!(metering.policy.snapshot_version, 1);
        assert_eq!(metering.policy.min_accept_work_units, 100);
        assert_eq!(
            metering.policy.challenge_success_bounty_per_work_unit_den,
            192
        );
        assert_eq!(metering.derived.path, "Revealed");
        assert_eq!(metering.derived.challenge_bonus_total, 2);
    }

    #[test]
    fn query_task_from_node_events_none_for_missing_task() {
        let events = vec![NodeEventRecord {
            event_type: "accept".into(),
            task_id: 10,
            from_status: "Open".into(),
            to_status: "Assigned".into(),
            actor: "worker-a".into(),
            tx_id: 1,
            block_height: 1,
            state_root: "s1".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        }];

        assert!(query_task_from_node_events(999, &events).is_none());
    }

    #[test]
    fn query_task_from_node_events_ignores_unknown_status_transition() {
        let events = vec![
            NodeEventRecord {
                event_type: "accept".into(),
                task_id: 7,
                from_status: "Open".into(),
                to_status: "Assigned".into(),
                actor: "worker-a".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "s1".into(),
                ts_unix_ms: 1,
                signer: None,
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "mystery".into(),
                task_id: 7,
                from_status: "Assigned".into(),
                to_status: "UNRECOGNIZED".into(),
                actor: "system".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "s2".into(),
                ts_unix_ms: 2,
                signer: None,
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
        ];

        let out = query_task_from_node_events(7, &events).expect("task expected");
        assert_eq!(out.status, TaskStatus::Assigned);
        assert_eq!(out.version, 1);
    }

    #[test]
    fn query_task_from_node_events_filters_invalid_signer_mismatch() {
        let events = vec![
            NodeEventRecord {
                event_type: "accept".into(),
                task_id: 8,
                from_status: "Open".into(),
                to_status: "Assigned".into(),
                actor: "worker-a".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "s1".into(),
                ts_unix_ms: 1,
                signer: Some("worker-b".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "commit".into(),
                task_id: 8,
                from_status: "Open".into(),
                to_status: "Committed".into(),
                actor: "worker-a".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "s2".into(),
                ts_unix_ms: 2,
                signer: Some("worker-a".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
        ];

        assert!(query_task_from_node_events(8, &events).is_none());
    }

    #[test]
    fn query_task_from_node_events_rejects_system_resolve_actor() {
        let events = vec![
            NodeEventRecord {
                event_type: "challenge".into(),
                task_id: 10,
                from_status: "Revealed".into(),
                to_status: "Challenged".into(),
                actor: "challenger-a".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "s1".into(),
                ts_unix_ms: 1,
                signer: Some("challenger-a".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: None,
                resolution_code: None,
                treasury_delta: Some(0),
                challenger_delta: Some(-5),
                bond_disposition: Some("posted".into()),
                metering: None,
            },
            NodeEventRecord {
                event_type: "resolve".into(),
                task_id: 10,
                from_status: "Challenged".into(),
                to_status: "Completed".into(),
                actor: "system".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "s2".into(),
                ts_unix_ms: 2,
                signer: Some("system".into()),
                challenger: Some("challenger-a".into()),
                tx_hash: None,
                resolution_code: Some("completed".into()),
                treasury_delta: Some(0),
                challenger_delta: Some(0),
                bond_disposition: Some("forfeited".into()),
                metering: None,
            },
        ];

        let out = query_task_from_node_events(10, &events).expect("task expected");
        assert_eq!(out.status, TaskStatus::Challenged);
        assert_eq!(out.version, 1);
    }

    #[test]
    fn query_events_response_applies_same_trust_and_transition_filters() {
        let events = vec![
            NodeEventRecord {
                event_type: "accept".into(),
                task_id: 9,
                from_status: "Open".into(),
                to_status: "Assigned".into(),
                actor: "worker-a".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "s1".into(),
                ts_unix_ms: 1,
                signer: Some("worker-a".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "commit".into(),
                task_id: 9,
                from_status: "Open".into(),
                to_status: "Committed".into(),
                actor: "worker-a".into(),
                tx_id: 2,
                block_height: 2,
                state_root: "s2".into(),
                ts_unix_ms: 2,
                signer: Some("worker-a".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
            NodeEventRecord {
                event_type: "reveal".into(),
                task_id: 9,
                from_status: "Committed".into(),
                to_status: "Revealed".into(),
                actor: "worker-a".into(),
                tx_id: 3,
                block_height: 3,
                state_root: "s3".into(),
                ts_unix_ms: 3,
                signer: Some("worker-b".into()),
                challenger: None,
                tx_hash: None,
                resolution_code: None,
                treasury_delta: None,
                challenger_delta: None,
                bond_disposition: None,
                metering: None,
            },
        ];

        let out = query_events_response(9, 20, &events, &[]).expect("events expected");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_type, "accept");
    }

    #[test]
    fn parse_event_log_kv_preserves_quoted_values_with_spaces() {
        let line = "[event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000 resolution_code=\"timeout reached\" bond_disposition='forfeit all'";
        let kv = parse_event_log_kv(line);

        assert_eq!(kv.get("event_type").map(String::as_str), Some("resolve"));
        assert_eq!(
            kv.get("resolution_code").map(String::as_str),
            Some("timeout reached")
        );
        assert_eq!(
            kv.get("bond_disposition").map(String::as_str),
            Some("forfeit all")
        );
    }

    #[test]
    fn load_node_events_parses_llm_metering_audit_block() {
        let root = tempfile::tempdir().expect("tempdir");
        let run = root.path().join("run");
        fs::create_dir_all(&run).expect("create run dir");
        let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
        fs::write(run.join("node1.log"), line).expect("write log");

        let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
        assert_eq!(loaded.events.len(), 1);
        let metering = loaded.events[0]
            .metering
            .as_ref()
            .expect("metering expected");
        assert_eq!(metering.normalized_work_units, 192);
        assert_eq!(metering.policy.snapshot_version, 1);
        assert_eq!(metering.policy.min_accept_work_units, 100);
        assert_eq!(
            metering.policy.challenge_success_bounty_per_work_unit_den,
            192
        );
        assert_eq!(metering.derived.path, "Completed");
        assert_eq!(metering.derived.challenge_bonus_total, 2);
    }

    #[test]
    fn load_node_events_skips_metering_block_with_u64_overflow_fields() {
        let root = tempfile::tempdir().expect("tempdir");
        let run = root.path().join("run");
        fs::create_dir_all(&run).expect("create run dir");
        let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=18446744073709551616 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384\n";
        fs::write(run.join("node1.log"), line).expect("write log");

        let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
        assert_eq!(loaded.events.len(), 1);
        assert!(
            loaded.events[0].metering.is_none(),
            "overflowing metering u64 fields must fail closed instead of truncating"
        );
    }

    #[test]
    fn load_node_events_skips_metering_block_with_zero_policy_denominator() {
        let root = tempfile::tempdir().expect("tempdir");
        let run = root.path().join("run");
        fs::create_dir_all(&run).expect("create run dir");
        let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=0 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384\n";
        fs::write(run.join("node1.log"), line).expect("write log");

        let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
        assert_eq!(loaded.events.len(), 1);
        assert!(
            loaded.events[0].metering.is_none(),
            "zero-denominator metering policies must fail closed instead of reporting derived incentives"
        );
    }

    #[test]
    fn load_node_events_recent_tail_marks_truncation_but_authoritative_keeps_history() {
        let root = tempfile::tempdir().expect("tempdir");
        let run = root.path().join("run");
        fs::create_dir_all(&run).expect("create run dir");

        let old_event = "2026-03-03T20:10:11Z INFO node [event] event_type=challenge task_id=7 from_status=Revealed to_status=Challenged actor=challenger-a tx_id=1 block_height=1 state_root=s1 ts_unix_ms=1000 challenger=challenger-a challenger_delta=-5 bond_disposition=posted\n";
        let filler = "x".repeat(600);
        let new_event = "2026-03-03T20:10:12Z INFO node [event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 signer=authority resolution_code=completed challenger=challenger-a challenger_delta=0 bond_disposition=forfeited\n";
        fs::write(
            run.join("node1.log"),
            format!("{old_event}{filler}\n{new_event}"),
        )
        .expect("write log");

        std::env::set_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES", "400");
        let recent = load_node_events_from_root(root.path(), NodeEventScanMode::RecentTail);
        std::env::remove_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES");

        assert!(recent.truncated);
        assert_eq!(recent.mode, NodeEventScanMode::RecentTail);
        assert_eq!(recent.events.len(), 1);
        assert_eq!(recent.events[0].event_type, "resolve");

        let authoritative =
            load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
        assert!(!authoritative.truncated);
        assert_eq!(authoritative.mode, NodeEventScanMode::Authoritative);
        assert_eq!(authoritative.events.len(), 2);
        assert_eq!(authoritative.events[0].event_type, "challenge");
        assert_eq!(authoritative.events[1].event_type, "resolve");
    }

    #[test]
    fn parse_event_log_kv_supports_prefixed_runtime_noise() {
        let line = "2026-03-03T20:10:11Z INFO node [event] event_type=commit task_id=7 from_status=Accepted to_status=Committed actor=did:trnm:worker tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000";
        let event_line = &line[line.find("[event]").expect("event marker")..];
        let kv = parse_event_log_kv(event_line);
        assert_eq!(kv.get("event_type").map(String::as_str), Some("commit"));
        assert_eq!(kv.get("task_id").map(String::as_str), Some("7"));
    }

    fn faucet_env_test_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn clear_faucet_env() {
        std::env::remove_var("TRNM_RPC_FAUCET_WINDOW_SECONDS");
        std::env::remove_var("TRNM_RPC_FAUCET_MAX_REQUESTS");
    }

    #[test]
    fn faucet_env_parsing_enforces_minimums() {
        let _guard = faucet_env_test_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        clear_faucet_env();

        std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "0");
        std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "0");

        let window = env_u64_with_min(
            "TRNM_RPC_FAUCET_WINDOW_SECONDS",
            FAUCET_WINDOW_SECONDS_DEFAULT,
            FAUCET_WINDOW_SECONDS_MIN,
        );
        let max_requests = env_u32_with_min(
            "TRNM_RPC_FAUCET_MAX_REQUESTS",
            FAUCET_MAX_REQUESTS_DEFAULT,
            FAUCET_MAX_REQUESTS_MIN,
        );

        assert_eq!(window, FAUCET_WINDOW_SECONDS_MIN);
        assert_eq!(max_requests, FAUCET_MAX_REQUESTS_MIN);

        clear_faucet_env();
    }

    #[test]
    fn faucet_env_parsing_uses_defaults_for_invalid_values() {
        let _guard = faucet_env_test_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        clear_faucet_env();

        std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "bad");
        std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "bad");

        let window = env_u64_with_min(
            "TRNM_RPC_FAUCET_WINDOW_SECONDS",
            FAUCET_WINDOW_SECONDS_DEFAULT,
            FAUCET_WINDOW_SECONDS_MIN,
        );
        let max_requests = env_u32_with_min(
            "TRNM_RPC_FAUCET_MAX_REQUESTS",
            FAUCET_MAX_REQUESTS_DEFAULT,
            FAUCET_MAX_REQUESTS_MIN,
        );

        assert_eq!(window, FAUCET_WINDOW_SECONDS_DEFAULT);
        assert_eq!(max_requests, FAUCET_MAX_REQUESTS_DEFAULT);

        clear_faucet_env();
    }

    #[test]
    fn faucet_env_parsing_accepts_surrounding_whitespace() {
        let _guard = faucet_env_test_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        clear_faucet_env();

        std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "  120  ");
        std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "\t9\n");

        let window = env_u64_with_min(
            "TRNM_RPC_FAUCET_WINDOW_SECONDS",
            FAUCET_WINDOW_SECONDS_DEFAULT,
            FAUCET_WINDOW_SECONDS_MIN,
        );
        let max_requests = env_u32_with_min(
            "TRNM_RPC_FAUCET_MAX_REQUESTS",
            FAUCET_MAX_REQUESTS_DEFAULT,
            FAUCET_MAX_REQUESTS_MIN,
        );

        assert_eq!(window, 120);
        assert_eq!(max_requests, 9);

        clear_faucet_env();
    }

    #[test]
    fn read_log_tail_returns_recent_lines() {
        let tmp = unique_tmp_path("trnm-rpc-tail-test", "log");
        fs::write(
            &tmp,
            "line1
line2
[event] event_type=commit task_id=1 tx_id=1 block_height=1
",
        )
        .expect("write temp log");
        let tail = read_log_tail(&tmp, 80).expect("tail text");
        assert!(tail.contains("[event] event_type=commit"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn read_log_tail_keeps_first_line_when_tail_starts_on_newline_boundary() {
        let tmp = unique_tmp_path("trnm-rpc-tail-boundary", "log");
        let content = "line1\n[event] event_type=commit task_id=7 tx_id=11 block_height=3\n";
        fs::write(&tmp, content).expect("write temp log");

        let start = "line1\n".len() as u64;
        let tail_bytes = content.len() as u64 - start;
        let tail = read_log_tail(&tmp, tail_bytes).expect("tail text");

        assert!(tail.starts_with("[event] event_type=commit"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn read_log_tail_tolerates_non_utf8_bytes() {
        let tmp = unique_tmp_path("trnm-rpc-tail-binary", "log");
        let mut bytes = vec![0xff, 0xfe, b'\n'];
        bytes.extend_from_slice(b"[event] event_type=commit task_id=9 tx_id=1 block_height=1\n");
        fs::write(&tmp, bytes).expect("write temp binary log");

        let tail = read_log_tail(&tmp, 1024).expect("tail text");
        assert!(tail.contains("[event] event_type=commit task_id=9"));
        let _ = fs::remove_file(tmp);
    }

    #[test]
    fn discover_default_node_event_log_sources_includes_dynamic_node4_and_nightly_logs() {
        let root = unique_tmp_path("trnm-rpc-log-root", "dir");
        let run_dir = root.join("run");
        fs::create_dir_all(&run_dir).expect("create run dir");
        fs::write(run_dir.join("node1.log"), "").expect("write node1");
        fs::write(run_dir.join("node4.log"), "").expect("write node4");
        fs::write(run_dir.join("nightly-bft.log"), "").expect("write nightly");
        fs::write(run_dir.join("notes.txt"), "").expect("write txt");

        let got = discover_default_node_event_log_sources(&root);

        assert!(got.contains(&run_dir.join("node1.log")));
        assert!(got.contains(&run_dir.join("node4.log")));
        assert!(got.contains(&run_dir.join("nightly-bft.log")));
        assert!(!got.contains(&run_dir.join("notes.txt")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_node_event_log_sources_prefers_manifest_and_env_over_fixed_defaults() {
        let _guard = lock_env();
        let root = unique_tmp_path("trnm-rpc-log-sources", "dir");
        let run_dir = root.join("run");
        let manifest_dir = root.join("cfg");
        fs::create_dir_all(&run_dir).expect("create run dir");
        fs::create_dir_all(&manifest_dir).expect("create manifest dir");

        let env_log = root.join("env-node4.log");
        let manifest_log = manifest_dir.join("nightly.log");
        let manifest = manifest_dir.join("sources.txt");
        fs::write(&env_log, "").expect("write env log");
        fs::write(&manifest_log, "").expect("write manifest log");
        fs::write(&manifest, "# comment\nnightly.log\n").expect("write manifest");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::set_var(
                NODE_EVENT_LOG_SOURCES_ENV,
                env_log.to_string_lossy().to_string(),
            );
            std::env::set_var(
                NODE_EVENT_LOG_MANIFEST_ENV,
                manifest.to_string_lossy().to_string(),
            );
        }

        let got = load_node_event_log_sources(&root);

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert!(got.contains(&env_log));
        assert!(got.contains(&manifest_log));
        assert_eq!(got.len(), 2, "custom sources should replace defaults");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_latest_node_events_reads_events_from_configured_node4_source() {
        let _guard = lock_env();
        let path = unique_tmp_path("trnm-rpc-node4", "log");
        fs::write(
            &path,
            "[event] event_type=commit task_id=44 tx_id=7 block_height=9 actor=node4 from_status=ASSIGNED to_status=COMPLETED state_root=abc signer=node4\n",
        )
        .expect("write node4 log");

        let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
        let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
        unsafe {
            std::env::set_var(
                NODE_EVENT_LOG_SOURCES_ENV,
                path.to_string_lossy().to_string(),
            );
            std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV);
        }

        let got = load_latest_node_events();

        match prev_sources {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
        }
        match prev_manifest {
            Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
            None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
        }

        assert!(got.iter().any(|evt| {
            evt.task_id == 44
                && evt.tx_id == 7
                && evt.block_height == 9
                && evt.actor == "node4"
                && evt.signer.as_deref() == Some("node4")
        }));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_quarantine_records_deduplicates_same_batch_entries() {
        let path = unique_tmp_path("ingress-quarantine-batch", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);

        let appended = append_quarantine_records(
            &path,
            &[
                IngressQuarantineRecord {
                    source_path: path.display().to_string(),
                    line_number: 2,
                    line_hash: 7,
                    raw_line: "not-json".to_string(),
                    error: "expected value".to_string(),
                    quarantined_at_unix_ms: 1,
                },
                IngressQuarantineRecord {
                    source_path: path.display().to_string(),
                    line_number: 2,
                    line_hash: 7,
                    raw_line: "not-json".to_string(),
                    error: "expected value".to_string(),
                    quarantined_at_unix_ms: 1,
                },
            ],
        )
        .expect("append duplicated batch");
        assert!(
            appended == 1,
            "duplicate malformed rows in the same batch must not inflate quarantine accounting: {appended}"
        );

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "batch dedup should persist exactly one entry"
        );

        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_quarantines_malformed_lines_with_accounting() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        let oversized_malformed = format!("not-json-{}", "x".repeat(5000));
        let mut fixture = String::from(
            "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
        );
        fixture.push_str(&oversized_malformed);
        fixture.push('\n');
        fs::write(&path, fixture).expect("write ingress fixture");

        let records = load_ingress_records();
        assert_eq!(
            records.len(),
            1,
            "valid ingress rows should survive salvage"
        );

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "malformed ingress row should be quarantined"
        );
        assert_eq!(entries[0]["line_number"], 2);
        let raw_line = entries[0]["raw_line"]
            .as_str()
            .expect("quarantine raw_line should be a string");
        assert_eq!(
            raw_line.len(),
            4096,
            "quarantine raw_line should be bounded"
        );
        assert!(
            oversized_malformed.starts_with(raw_line),
            "quarantine raw_line should preserve the malformed prefix"
        );
        assert_eq!(entries[0]["source_path"], path.display().to_string());

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_does_not_duplicate_existing_quarantine_accounting() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine-dedupe", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(&path, "not-json\n").expect("write malformed ingress fixture");

        let first = load_ingress_records();
        let second = load_ingress_records();
        assert!(first.is_empty());
        assert!(second.is_empty());

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "reloading identical malformed ingress rows should not duplicate quarantine accounting"
        );
        assert_eq!(entries[0]["line_number"], 1);
        assert_eq!(entries[0]["raw_line"], "not-json");

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_dedupes_quarantine_accounting_for_whitespace_only_malformed_replays() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine-whitespace-dedupe", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
        let first = load_ingress_records();
        assert!(first.is_empty());

        fs::write(&path, "  not-json  \n").expect("rewrite malformed ingress fixture with padding");
        let second = load_ingress_records();
        assert!(second.is_empty());

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "whitespace-only malformed replays should not duplicate quarantine accounting"
        );
        assert_eq!(entries[0]["line_number"], 1);
        assert_eq!(entries[0]["raw_line"], "not-json");

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_reuses_legacy_quarantine_fingerprints_without_line_hash() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine-legacy-dedupe", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
        fs::write(
            &quarantine,
            format!(
                "{{\"source_path\":\"{}\",\"line_number\":1,\"raw_line\":\"  not-json  \",\"error\":\"legacy\",\"quarantined_at_unix_ms\":1}}\n",
                path.display()
            ),
        )
        .expect("seed legacy quarantine fixture");

        let records = load_ingress_records();
        assert!(records.is_empty());

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "legacy quarantine rows without line_hash should still suppress duplicate accounting"
        );
        assert!(
            entries[0].get("line_hash").is_none(),
            "fixture should remain legacy-shaped"
        );
        assert_eq!(entries[0]["raw_line"], "  not-json  ");

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_reuses_legacy_quarantine_fingerprints_with_padded_source_path() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine-legacy-source-path-padding", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
        fs::write(
            &quarantine,
            format!(
                "{{\"source_path\":\"  {}  \",\"line_number\":1,\"raw_line\":\"not-json\",\"error\":\"legacy\",\"quarantined_at_unix_ms\":1}}\n",
                path.display()
            ),
        )
        .expect("seed padded legacy quarantine fixture");

        let records = load_ingress_records();
        assert!(records.is_empty());

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "legacy padded source_path should still suppress duplicate quarantine accounting"
        );
        assert_eq!(entries[0]["raw_line"], "not-json");
        assert!(
            entries[0].get("line_hash").is_none(),
            "fixture should remain legacy-shaped"
        );

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn load_ingress_records_reuses_legacy_quarantine_fingerprints_with_string_line_number() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine-legacy-string-line-number", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
        fs::write(
            &quarantine,
            format!(
                "{{\"source_path\":\"{}\",\"line_number\":\"1\",\"raw_line\":\"not-json\",\"error\":\"legacy\",\"quarantined_at_unix_ms\":1}}\n",
                path.display()
            ),
        )
        .expect("seed string line-number legacy quarantine fixture");

        let records = load_ingress_records();
        assert!(records.is_empty());

        let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
        let entries: Vec<serde_json::Value> = quarantine_raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "legacy string line_number should still suppress duplicate quarantine accounting"
        );
        assert_eq!(entries[0]["line_number"], "1");
        assert!(
            entries[0].get("line_hash").is_none(),
            "fixture should remain legacy-shaped"
        );

        std::env::remove_var("TRNM_RPC_INGRESS_FILE");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
    }

    #[test]
    fn atomic_write_text_file_replaces_without_leaving_temp_files() {
        let path = unique_tmp_path("rpc-atomic-write", "json");
        let parent = path.parent().expect("temp parent").to_path_buf();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();
        let _ = fs::remove_file(&path);

        atomic_write_text_file(&path, "{\"ok\":true}\n").expect("atomic write succeeds");
        let raw = fs::read_to_string(&path).expect("read atomic target");
        assert_eq!(raw, "{\"ok\":true}\n");

        let leftovers: Vec<_> = fs::read_dir(&parent)
            .expect("read temp dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with(&format!(".{}.tmp-", file_name)))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary atomic-write files should be cleaned"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_latest_adapter_records_skips_invalid_jsonl_rows() {
        let dir = run_root().join("run/worker-agent");
        fs::create_dir_all(&dir).expect("create worker-agent dir");

        let mut backup: Vec<(PathBuf, Vec<u8>)> = vec![];
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let is_adapter = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                    .unwrap_or(false);
                if !is_adapter {
                    continue;
                }
                if let Ok(bytes) = fs::read(&path) {
                    backup.push((path.clone(), bytes));
                }
                let _ = fs::remove_file(&path);
            }
        }

        let fixture = dir.join(format!("tx-adapter-99991231-{}.jsonl", std::process::id()));
        fs::write(
            &fixture,
            "not-json\n{\"ts\":1772074584,\"mode\":\"mock\",\"kind\":\"commit\",\"task_id\":101001,\"worker\":\"worker1\",\"commit_hash\":\"764c7baf3e1d3d325511cdc3d7836fbc1fa71a289bd669edcc4b55d6baaee9d7\",\"nonce\":101001,\"tx_hash\":\"7336b90d593ebe324cb4b3e41e7e9d86d1e2418f230cca0162ca1d539f32c2b9\",\"status\":\"accepted\",\"rc\":0}\n",
        )
        .expect("write adapter fixture");

        let records = load_latest_adapter_records();
        assert_eq!(records.len(), 1, "only valid JSONL rows should be loaded");
        assert_eq!(records[0].task_id, 101001);

        let _ = fs::remove_file(&fixture);
        for (path, bytes) in backup {
            let _ = fs::write(path, bytes);
        }
    }
}
