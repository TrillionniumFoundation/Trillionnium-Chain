use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::{Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_oracle::{
    emit_oracle_validation_observation, validate_snapshot_observed, OraclePolicy, OracleSnapshot,
};
use trnm_rpc::{
    get_tx, query_account_state, submit_tx, validate_trnm_address, AccountBalanceQueryResponse,
    AccountNonceQueryResponse, AccountState, EventQueryResponse, FaucetRequestResponse, GetTxError,
    GovParamQueryResponse, GovProposalQueryResponse, InMemoryTransferLedger,
    MessageRequestQueryResponse, OracleValidateSnapshotRequest, OracleValidateSnapshotResponse,
    RequestFullQueryResponse, RpcErrorResponse, TaskQueryResponse, TxLifecycleRecord,
};
use trnm_state::StateStore;
use trnm_types::{
    AuditEvent, CapabilityToken, GovParamObject, GovProposalObject, GovProposalStatus,
    IdentityRegistry, PrivacyTier, RequestStatus, TaskMetadata, TaskStatus, TransferTx,
};

const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
const QUERY_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
const QUERY_FULL_LIMIT_MAX: usize = 200;
const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
const DISPATCH_OPEN_LIMIT_MAX: usize = 100;
const CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT: usize = 20;
const CHALLENGE_TREASURY_EVENTS_LIMIT_MAX: usize = 200;
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const NODE_EVENT_LOG_TAIL_BYTES_DEFAULT: u64 = 4 * 1024 * 1024;
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
    #[command(
        name = "oracle.validate_snapshot",
        visible_alias = "oracle-validate-snapshot"
    )]
    OracleValidateSnapshot {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        now_ts_ms: Option<u64>,
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
struct MarketMatchResult {
    task_id: u64,
    winner: String,
    price: u128,
    status: String,
    match_policy: String,
    matched_bid_count: usize,
    winner_reputation: i64,
    effective_score: u128,
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
    RecentTail,
}

impl NodeEventScanMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
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

fn node_event_log_tail_bytes() -> u64 {
    std::env::var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(NODE_EVENT_LOG_TAIL_BYTES_MAX))
        .filter(|v| *v > 0)
        .unwrap_or(NODE_EVENT_LOG_TAIL_BYTES_DEFAULT)
}

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
    let tail_bytes = node_event_log_tail_bytes();
    let mut lines = Vec::new();
    let mut truncated = false;
    for p in candidates {
        let raw = match mode {
            NodeEventScanMode::Authoritative => fs::read_to_string(&p).ok(),
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

        let normalize_opt = |k: &str| {
            kv.get(k).and_then(|v| {
                if v.is_empty() || v == "-" {
                    None
                } else {
                    Some(v.clone())
                }
            })
        };

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

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)
        .map_err(|err| anyhow!("failed to read {}: {}", path.display(), err))?;
    serde_json::from_str(&raw).map_err(|err| anyhow!("failed to parse {}: {}", path.display(), err))
}

fn oracle_validate_snapshot_response(
    snapshot_path: &Path,
    policy_path: &Path,
    now_ts_ms: u64,
) -> Result<OracleValidateSnapshotResponse> {
    let snapshot: OracleSnapshot = read_json_file(snapshot_path)?;
    let policy: OraclePolicy = read_json_file(policy_path)?;
    let report = validate_snapshot_observed(&policy, &snapshot, now_ts_ms);

    Ok(OracleValidateSnapshotResponse {
        ok: report.ok,
        now_ts_ms,
        observation: report.observation,
        metrics: report.metrics,
        error: report.error,
    })
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
            _ if ch.is_control() => Some(' '),
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
            _ if ch.is_control() => Some(' '),
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
            _ if ch.is_control() => Some(' '),
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
                // keep the strongest reputation signal to avoid accidental downgrade.
                .and_modify(|existing| *existing = (*existing).max(rep))
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

#[derive(Debug, Serialize)]
struct MarketScoreConfigOutput {
    price_weight: u128,
    reputation_weight: u128,
    reputation_clamp: i64,
}

impl From<MarketScoreConfig> for MarketScoreConfigOutput {
    fn from(value: MarketScoreConfig) -> Self {
        Self {
            price_weight: value.price_weight,
            reputation_weight: value.reputation_weight,
            reputation_clamp: value.reputation_clamp,
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

fn clamp_reputation_for_market(reputation: i64, cfg: MarketScoreConfig) -> i64 {
    reputation.clamp(-cfg.reputation_clamp, cfg.reputation_clamp)
}

fn market_effective_score_with_config(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> u128 {
    let rep = clamp_reputation_for_market(reputation, cfg);
    let base = price.saturating_mul(cfg.price_weight);
    if rep >= 0 {
        base.saturating_sub((rep as u128).saturating_mul(cfg.reputation_weight))
    } else {
        base.saturating_add((rep.unsigned_abs() as u128).saturating_mul(cfg.reputation_weight))
    }
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

#[derive(Debug, Serialize)]
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
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

fn append_quarantine_records(path: &Path, entries: &[IngressQuarantineRecord]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let quarantine_path = ingress_quarantine_file_for(path);
    let _lock = acquire_market_file_lock(&quarantine_path)?;
    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&quarantine_path)?;
    for entry in entries {
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
    }
    file.sync_all()?;
    Ok(())
}

fn load_ingress_records() -> Vec<MessageIngressRecord> {
    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(&path) else {
        return vec![];
    };
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<MessageIngressRecord>(line) {
            Ok(record) => records.push(record),
            Err(err) => quarantined.push(IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: idx + 1,
                line_hash: stable_line_hash(line),
                raw_line: line.to_string(),
                error: err.to_string(),
                quarantined_at_unix_ms: now_ms(),
            }),
        }
    }
    if !quarantined.is_empty() {
        if let Err(err) = append_quarantine_records(&path, &quarantined) {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE_WRITE] path={} quarantined={} err={}",
                path.display(),
                quarantined.len(),
                err
            );
        } else {
            eprintln!(
                "[trnm-rpc][warn][INGRESS_QUARANTINE] path={} quarantined={} quarantine_path={}",
                path.display(),
                quarantined.len(),
                ingress_quarantine_file_for(&path).display()
            );
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
        if task_type.is_empty() {
            bail!("metadata.task_type must not be empty");
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
    if requested == 0 {
        eprintln!(
            "[trnm-rpc][warn][RPC_CAP] op={} requested_limit=0 fallback_default={} max={}",
            op, default_limit, max_limit
        );
        return default_limit;
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

fn normalize_tx_hash_lookup(raw: &str) -> String {
    let mut normalized = raw.trim_matches(|c: char| {
        c.is_ascii_whitespace() || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
    });

    loop {
        let is_wrapped = normalized.len() >= 2
            && ["\"", "'", "`"]
                .iter()
                .any(|q| normalized.starts_with(q) && normalized.ends_with(q));

        if is_wrapped {
            normalized = normalized[1..normalized.len() - 1].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
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
                        || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
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
                                || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
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

fn http_json_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn http_text_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
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
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n")
            || buf.windows(2).any(|window| window == b"\n\n")
        {
            break;
        }
    }

    Ok(buf)
}

fn parse_http_get_target(first_line: &str) -> Option<&str> {
    let line = first_line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }

    let first_sp = line.find(' ')?;
    let method = &line[..first_sp];
    if method != "GET" {
        return None;
    }

    let mut rest = line[first_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return None;
    }

    let second_sp = rest.find(' ')?;
    let target = &rest[..second_sp];
    if !target.starts_with('/') {
        return None;
    }
    rest = rest[second_sp + 1..].trim_start_matches([' ', '\t']);
    if rest.is_empty() || !rest.starts_with("HTTP/") {
        return None;
    }

    Some(target)
}

fn parse_http_get_path(first_line: &str) -> Option<&str> {
    let target = parse_http_get_target(first_line)?;
    Some(target.split('?').next().unwrap_or(target))
}

fn decode_http_query_component(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push(((hi << 4) | lo) as u8);
                i += 3;
            }
            b'%' => return None,
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn parse_http_query_params(target: &str) -> Option<BTreeMap<String, String>> {
    let (_, query) = target.split_once('?')?;
    let mut out = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_http_query_component(raw_key)?;
        if key.is_empty() {
            return None;
        }
        let value = decode_http_query_component(raw_value)?;
        if out.insert(key, value).is_some() {
            // Fail-closed on duplicate keys to keep query parsing deterministic.
            return None;
        }
    }
    Some(out)
}

fn http_json_error(status_line: &str, code: &str, message: &str) -> String {
    let body = serde_json::json!({
        "ok": false,
        "code": code,
        "message": message,
    })
    .to_string();
    http_json_response(status_line, &body)
}

fn parse_oracle_validate_snapshot_target(
    target: &str,
) -> Result<OracleValidateSnapshotRequest, String> {
    let Some(query) = parse_http_query_params(target) else {
        return Err("invalid query string".to_string());
    };

    for key in query.keys() {
        if !matches!(key.as_str(), "snapshot" | "policy" | "now_ts_ms") {
            return Err(format!("unknown query parameter: {}", key));
        }
    }

    let Some(snapshot) = query.get("snapshot") else {
        return Err("missing snapshot".to_string());
    };
    if snapshot.trim().is_empty() {
        return Err("empty snapshot".to_string());
    }

    let Some(policy) = query.get("policy") else {
        return Err("missing policy".to_string());
    };
    if policy.trim().is_empty() {
        return Err("empty policy".to_string());
    }

    let now_ts_ms = match query.get("now_ts_ms") {
        Some(raw) => Some(
            raw.parse::<u64>()
                .map_err(|_| "invalid now_ts_ms".to_string())?,
        ),
        None => None,
    };

    Ok(OracleValidateSnapshotRequest {
        snapshot: snapshot.clone(),
        policy: policy.clone(),
        now_ts_ms,
    })
}

fn prometheus_escape_label_value(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn rpc_service_prometheus_text() -> String {
    "# HELP trnm_rpc_service_up Trnm RPC service liveness flag.\n# TYPE trnm_rpc_service_up gauge\ntrnm_rpc_service_up{service=\"trnm-rpc\"} 1\n# HELP trnm_rpc_service_info Trnm RPC service info metric.\n# TYPE trnm_rpc_service_info gauge\ntrnm_rpc_service_info{service=\"trnm-rpc\",version=\"1\"} 1\n".to_string()
}

fn oracle_metrics_prometheus_text(out: &OracleValidateSnapshotResponse) -> String {
    let feed_id = prometheus_escape_label_value(&out.observation.feed_id);
    let outcome = prometheus_escape_label_value(&out.observation.outcome);
    let labels = format!("feed_id=\"{feed_id}\",outcome=\"{outcome}\"");
    let ok = if out.ok { 1 } else { 0 };

    format!(
        "# HELP oracle_validation_ok Oracle validation success flag for the supplied snapshot.\n# TYPE oracle_validation_ok gauge\noracle_validation_ok{{{labels}}} {ok}\n# HELP oracle_stale_reject_total Oracle stale snapshot rejection counter.\n# TYPE oracle_stale_reject_total counter\noracle_stale_reject_total{{{labels}}} {}\n# HELP oracle_quorum_reject_total Oracle insufficient-source rejection counter.\n# TYPE oracle_quorum_reject_total counter\noracle_quorum_reject_total{{{labels}}} {}\n# HELP oracle_drift_reject_total Oracle deviation rejection counter.\n# TYPE oracle_drift_reject_total counter\noracle_drift_reject_total{{{labels}}} {}\n# HELP oracle_source_cardinality Oracle source cardinality observed for the snapshot.\n# TYPE oracle_source_cardinality gauge\noracle_source_cardinality{{{labels}}} {}\n# HELP accepted_total Accepted snapshot counter using baseline naming.\n# TYPE accepted_total counter\naccepted_total{{{labels}}} {}\n# HELP sample_count Sample counter using baseline naming.\n# TYPE sample_count counter\nsample_count{{{labels}}} {}\n# HELP oracle_snapshot_ts_ms Snapshot timestamp in unix milliseconds.\n# TYPE oracle_snapshot_ts_ms gauge\noracle_snapshot_ts_ms{{{labels}}} {}\n",
        out.metrics.oracle_stale_reject_total,
        out.metrics.oracle_quorum_reject_total,
        out.metrics.oracle_drift_reject_total,
        out.metrics.oracle_source_cardinality,
        out.metrics.accepted_total,
        out.metrics.sample_count,
        out.observation.snapshot_ts_ms,
    )
}

fn http_oracle_validate_snapshot_response(target: &str) -> String {
    let request = match parse_oracle_validate_snapshot_target(target) {
        Ok(request) => request,
        Err(message) => return http_json_error("400 Bad Request", "BAD_REQUEST", &message),
    };
    let now_ts_ms = request.now_ts_ms.unwrap_or_else(|| now_ms() as u64);

    match oracle_validate_snapshot_response(
        Path::new(&request.snapshot),
        Path::new(&request.policy),
        now_ts_ms,
    ) {
        Ok(out) => {
            let _ = emit_oracle_validation_observation(&out.observation, &out.metrics);
            let body = serde_json::to_string(&out)
                .unwrap_or_else(|_| "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string());
            http_json_response("200 OK", &body)
        }
        Err(err) => http_json_error("400 Bad Request", "BAD_REQUEST", &err.to_string()),
    }
}

fn http_oracle_metrics_response(target: &str) -> String {
    let request = match parse_oracle_validate_snapshot_target(target) {
        Ok(request) => request,
        Err(message) => return http_json_error("400 Bad Request", "BAD_REQUEST", &message),
    };
    let now_ts_ms = request.now_ts_ms.unwrap_or_else(|| now_ms() as u64);

    match oracle_validate_snapshot_response(
        Path::new(&request.snapshot),
        Path::new(&request.policy),
        now_ts_ms,
    ) {
        Ok(out) => {
            let _ = emit_oracle_validation_observation(&out.observation, &out.metrics);
            http_text_response("200 OK", &oracle_metrics_prometheus_text(&out))
        }
        Err(err) => http_json_error("400 Bad Request", "BAD_REQUEST", &err.to_string()),
    }
}

fn http_metrics_response(target: &str) -> String {
    let mut body = rpc_service_prometheus_text();

    match parse_http_query_params(target) {
        None if target.contains('?') => {
            return http_json_error("400 Bad Request", "BAD_REQUEST", "invalid query string")
        }
        None => return http_text_response("200 OK", &body),
        Some(query) => {
            let has_oracle_query = query.contains_key("snapshot")
                || query.contains_key("policy")
                || query.contains_key("now_ts_ms");
            if !has_oracle_query {
                return http_text_response("200 OK", &body);
            }
        }
    }

    let request = match parse_oracle_validate_snapshot_target(target) {
        Ok(request) => request,
        Err(message) => return http_json_error("400 Bad Request", "BAD_REQUEST", &message),
    };
    let now_ts_ms = request.now_ts_ms.unwrap_or_else(|| now_ms() as u64);

    match oracle_validate_snapshot_response(
        Path::new(&request.snapshot),
        Path::new(&request.policy),
        now_ts_ms,
    ) {
        Ok(out) => {
            let _ = emit_oracle_validation_observation(&out.observation, &out.metrics);
            body.push_str(&oracle_metrics_prometheus_text(&out));
            http_text_response("200 OK", &body)
        }
        Err(err) => http_json_error("400 Bad Request", "BAD_REQUEST", &err.to_string()),
    }
}

fn http_service_response_for_target(target: Option<&str>) -> String {
    match target {
        Some("/health") => {
            let body = serde_json::json!({
                "ok": true,
                "service": "trnm-rpc",
                "ts_unix_ms": now_ms(),
                "version": 1
            })
            .to_string();
            http_json_response("200 OK", &body)
        }
        Some(target) => {
            let path = target.split('?').next().unwrap_or(target);
            match path {
                "/metrics" => http_metrics_response(target),
                "/oracle/validate_snapshot" => http_oracle_validate_snapshot_response(target),
                "/oracle/metrics" => http_oracle_metrics_response(target),
                _ => {
                    if path.starts_with("/query-task/") {
                        let task_id = path.trim_start_matches("/query-task/").parse::<u64>();
                        match task_id {
                            Ok(task_id) => {
                                let node_events =
                                    load_node_events(NodeEventScanMode::Authoritative);
                                let recs = load_latest_adapter_records();
                                match query_task_response(task_id, &node_events.events, &recs) {
                                    Ok(out) => {
                                        let body =
                                            serde_json::to_string(&out).unwrap_or_else(|_| {
                                                "{\"ok\":false,\"code\":\"SERDE_ERROR\"}"
                                                    .to_string()
                                            });
                                        http_json_response("200 OK", &body)
                                    }
                                    Err(err) => http_json_error(
                                        "404 Not Found",
                                        "NOT_FOUND",
                                        &err.to_string(),
                                    ),
                                }
                            }
                            Err(_) => {
                                http_json_error("400 Bad Request", "BAD_REQUEST", "invalid task_id")
                            }
                        }
                    } else if path.starts_with("/query-events/") {
                        let task_id = path.trim_start_matches("/query-events/").parse::<u64>();
                        match task_id {
                            Ok(task_id) => {
                                let node_events =
                                    load_node_events(NodeEventScanMode::Authoritative);
                                let recs = load_latest_adapter_records();
                                match query_events_response(
                                    task_id,
                                    QUERY_EVENTS_LIMIT_DEFAULT,
                                    &node_events.events,
                                    &recs,
                                ) {
                                    Ok(events) => {
                                        let body =
                                            serde_json::to_string(&events).unwrap_or_else(|_| {
                                                "{\"ok\":false,\"code\":\"SERDE_ERROR\"}"
                                                    .to_string()
                                            });
                                        http_json_response("200 OK", &body)
                                    }
                                    Err(err) => http_json_error(
                                        "404 Not Found",
                                        "NOT_FOUND",
                                        &err.to_string(),
                                    ),
                                }
                            }
                            Err(_) => {
                                http_json_error("400 Bad Request", "BAD_REQUEST", "invalid task_id")
                            }
                        }
                    } else if path.starts_with("/query-capability-audit/") {
                        let subject_or_token = path.trim_start_matches("/query-capability-audit/");
                        let registry = load_identity_registry(&identity_registry_file());
                        if let Some(token_id) =
                            resolve_capability_token_subject_or_token(&registry, subject_or_token)
                        {
                            match query_capability_audit(&registry, token_id) {
                                Ok(out) => {
                                    let body = serde_json::to_string(&out).unwrap_or_else(|_| {
                                        "{\"ok\":false,\"code\":\"SERDE_ERROR\"}".to_string()
                                    });
                                    http_json_response("200 OK", &body)
                                }
                                Err(err) => http_json_error(
                                    "404 Not Found",
                                    "NOT_FOUND",
                                    &err.to_rpc_error().message,
                                ),
                            }
                        } else {
                            http_json_error(
                                "404 Not Found",
                                "NOT_FOUND",
                                "token or subject not found",
                            )
                        }
                    } else {
                        let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
                        http_json_response("404 Not Found", body)
                    }
                }
            }
        }
        None => {
            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
            http_json_response("404 Not Found", body)
        }
    }
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
        let req = String::from_utf8_lossy(&req);
        let first = req.lines().next().unwrap_or("");
        let target = parse_http_get_target(first);
        let response = http_service_response_for_target(target);

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
    })
}

fn query_task_response(
    task_id: u64,
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
) -> Result<TaskQueryResponse> {
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
        events.push(EventQueryResponse {
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
        });
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

            events.push(EventQueryResponse {
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
            });
            if kind == "commit" {
                has_commit = true;
            }
            tx_id += 1;
        }
    }

    if events.is_empty() {
        bail!("events not found for task_id={}", task_id);
    }
    if events.len() > limit {
        let keep_from = events.len() - limit;
        events = events.split_off(keep_from);
    }
    Ok(events)
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
            let ids = [7001u64, 7999u64];
            let mut found: Option<GovParamObject> = None;
            for id in ids {
                if let Some(p) = st.get_param(id) {
                    if p.key == key {
                        found = Some(p);
                        break;
                    }
                }
            }
            let Some(p) = found else {
                bail!("param not found: {}", key);
            };
            let out = GovParamQueryResponse {
                key: p.key,
                value: p.value,
                version: p.version,
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
                next_allowed_unix_ms = entry.window_start_unix_ms + window_ms;
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
                events.push(EventQueryResponse {
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
                });
            }

            if events.len() > limit {
                let keep_from = events.len() - limit;
                events = events.split_off(keep_from);
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
                if task.status != "open" {
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
            if task.status != "open" {
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
            let winner_reputation = normalize_market_worker_key(&winner.worker)
                .and_then(|k| reputation.get(&k).copied())
                .unwrap_or(0);
            let winner_reputation_effective =
                clamp_reputation_for_market(winner_reputation, score_cfg);
            let base_score = winner.price.saturating_mul(score_cfg.price_weight);
            let reputation_weight = if winner_reputation_effective > 0 {
                (winner_reputation_effective as u128).saturating_mul(score_cfg.reputation_weight)
            } else {
                0
            };
            let penalty = if winner_reputation_effective < 0 {
                (winner_reputation_effective.unsigned_abs() as u128)
                    .saturating_mul(score_cfg.reputation_weight)
            } else {
                0
            };
            let winner_score = if winner_reputation_effective >= 0 {
                base_score.saturating_sub(reputation_weight)
            } else {
                base_score.saturating_add(penalty)
            };

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
                "winner_reputation_effective": winner_reputation_effective,
                "base_score": base_score,
                "reputation_weight": reputation_weight,
                "penalty": penalty,
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
        Command::OracleValidateSnapshot {
            snapshot,
            policy,
            now_ts_ms,
        } => {
            let out = oracle_validate_snapshot_response(
                &snapshot,
                &policy,
                now_ts_ms.unwrap_or_else(|| now_ms() as u64),
            )?;
            let _ = emit_oracle_validation_observation(&out.observation, &out.metrics);
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::Serve { host, port } => {
            serve_health(&host, port)?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
