use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::time::{Duration, Instant};
#[cfg(test)]
use std::{fs, io::Write};
use trnm_rpc::{
    get_tx, query_account_state, submit_tx, validate_trnm_address, AccountBalanceQueryResponse,
    AccountNonceQueryResponse, AccountState, EventQueryResponse, FaucetRequestResponse, GetTxError,
    MessageRequestQueryResponse, RequestFullQueryResponse, RpcErrorResponse,
    TaskMeteringQueryResponse,
};
#[cfg(test)]
use trnm_types::IdentityRegistry;
use trnm_types::{RequestStatus, TransferTx};
#[cfg(test)]
use trnm_types::{TaskMetadata, TaskMeteringSnapshot, TaskObject, TaskStatus};

mod capability;
mod envpaths;
mod fsutil;
mod health;
mod http;
mod ingress;
mod market_io;
mod market_score;
mod metering;
mod node_events;
mod persistence;
mod read_query;
mod request_query;
mod rpc_util;
mod runtime;
mod snapshot;
mod taskview;
mod treasury;
mod validate;

#[cfg(test)]
use crate::capability::resolve_capability_token_subject_or_token;
use crate::envpaths::{
    account_state_file, env_u32_with_min, env_u64_with_min, faucet_limits_file, ingress_file,
    market_bids_file, market_tasks_file, submit_message_max_bytes, tx_lifecycle_file,
};
#[cfg(test)]
use crate::envpaths::{market_lock_timeout_ms, market_reputation_file, task_state_file};
#[cfg(test)]
use crate::envpaths::{normalized_path_from_env, run_root};
#[cfg(test)]
use crate::fsutil::atomic_write_text_file;
use crate::health::serve_health;
#[cfg(test)]
use crate::http::{
    configure_health_stream, parse_http_get_path, parse_query_events_limit_from_path,
    read_http_request_head,
};
#[cfg(test)]
use crate::ingress::ingress_quarantine_file_for;
use crate::ingress::{
    is_same_submit_message_idempotency_scope, load_ingress_records, next_ingress_task_id,
    save_ingress_records,
};
#[cfg(test)]
use crate::market_io::market_lock_path;
use crate::market_io::{
    acquire_market_file_lock, load_market_bids, load_market_reputation, load_market_tasks,
    market_worker_tie_break_key, normalize_market_status_key, normalize_market_worker_key,
    save_market_bids, save_market_tasks,
};
#[cfg(test)]
use crate::market_score::market_effective_score;
use crate::market_score::{
    clamp_reputation_for_market, market_effective_score_with_config, market_score_config,
    MarketScoreConfigOutput,
};
#[cfg(test)]
use crate::metering::{
    parse_event_log_kv, parse_i128_kv_value, parse_u128_kv_value, parse_u64_kv_value,
};
#[cfg(test)]
use crate::node_events::{
    discover_default_node_event_log_sources, load_latest_node_events, load_node_event_log_sources,
    load_node_events_from_root, read_log_tail,
};
use crate::persistence::{
    accounts_to_ledger, ledger_to_accounts, load_account_state, load_faucet_limits,
    load_tx_lifecycle, save_account_state, save_faucet_limits, save_tx_lifecycle,
};
use crate::read_query::{
    handle_query_capability_audit, handle_query_events, handle_query_param, handle_query_proposal,
    handle_query_task,
};
use crate::request_query::{handle_query_request, handle_query_request_full};
use crate::rpc_util::{clamp_limit, rpc_fail};
#[cfg(test)]
use crate::rpc_util::resolve_ops_window;
use crate::runtime::{make_request_id, now_ms};
#[cfg(test)]
use crate::snapshot::query_task_from_state_snapshot;
#[cfg(test)]
use crate::snapshot::{governance_state, load_latest_adapter_records};
#[cfg(test)]
use crate::taskview::query_task_from_node_events;
#[cfg(test)]
use crate::taskview::query_events_response;
use crate::treasury::{handle_query_challenge_treasury, CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT};
#[cfg(test)]
use crate::treasury::summarize_challenge_treasury;
use crate::validate::{transition_request_status, validate_submit_message_metadata};

const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
const QUERY_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
const QUERY_FULL_LIMIT_MAX: usize = 200;
const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
const DISPATCH_OPEN_LIMIT_MAX: usize = 100;
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
pub(crate) struct AdapterRecord {
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
pub(crate) struct MarketTask {
    task_id: u64,
    creator: String,
    bounty: u128,
    description: String,
    status: String,
    created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MarketBid {
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
    pub(crate) result_hash: Option<String>,
    #[serde(default)]
    pub(crate) verifier_status: Option<String>,
    #[serde(default)]
    pub(crate) resolution_code: Option<String>,
    #[serde(default)]
    pub(crate) commit_tx_hash: Option<String>,
    #[serde(default)]
    pub(crate) reveal_tx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct NodeEventRecord {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) from_status: String,
    pub(crate) to_status: String,
    pub(crate) actor: String,
    pub(crate) tx_id: u64,
    pub(crate) block_height: u64,
    pub(crate) state_root: String,
    pub(crate) ts_unix_ms: u128,
    pub(crate) signer: Option<String>,
    pub(crate) challenger: Option<String>,
    pub(crate) tx_hash: Option<String>,
    pub(crate) resolution_code: Option<String>,
    pub(crate) treasury_delta: Option<i128>,
    pub(crate) challenger_delta: Option<i128>,
    pub(crate) bond_disposition: Option<String>,
    pub(crate) metering: Option<TaskMeteringQueryResponse>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OpsWindowArg {
    #[value(name = "24h")]
    H24,
    #[value(name = "7d")]
    D7,
    #[value(name = "custom")]
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeEventScanMode {
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
pub(crate) struct LoadedNodeEvents {
    pub(crate) events: Vec<NodeEventRecord>,
    pub(crate) mode: NodeEventScanMode,
    pub(crate) truncated: bool,
}

pub(crate) fn normalize_actor_or_signer(raw: &str) -> Option<String> {
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

#[derive(Debug, Serialize)]
pub(crate) struct IngressQuarantineRecord {
    source_path: String,
    line_number: usize,
    line_hash: u64,
    raw_line: String,
    error: String,
    quarantined_at_unix_ms: u128,
}

pub(crate) fn push_tail_limited<T>(items: &mut Vec<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    items.push(item);
    if items.len() > limit {
        let keep_from = items.len() - limit;
        items.drain(0..keep_from);
    }
}

pub(crate) fn normalize_tx_hash_lookup(raw: &str) -> String {
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

pub(crate) fn is_hex_like_tx_hash(raw: &str) -> bool {
    raw.strip_prefix("0x")
        .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Command::QueryTask { task_id } => handle_query_task(task_id)?,
        Command::QueryProposal { proposal_id } => handle_query_proposal(proposal_id)?,
        Command::QueryParam { key } => handle_query_param(&key)?,
        Command::QueryEvents { task_id, limit } => handle_query_events(task_id, limit)?,
        Command::QueryCapabilityAudit { token_id } => handle_query_capability_audit(token_id)?,
        Command::QueryChallengeTreasury {
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
        } => handle_query_challenge_treasury(
            limit,
            window,
            from_unix_ms,
            to_unix_ms,
            json,
            now_ms(),
        )?,
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
        Command::QueryRequest { request_id } => handle_query_request(&request_id)?,
        Command::QueryRequestFull { request_id, limit } => {
            handle_query_request_full(&request_id, limit)?
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
    fn parse_http_get_path_rejects_non_get_or_malformed_lines() {
        assert_eq!(parse_http_get_path("POST /health HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /health"), None);
        assert_eq!(parse_http_get_path("GET health HTTP/1.1"), None);
        assert_eq!(parse_http_get_path("GET /health\u{0001} HTTP/1.1"), None);
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
    fn market_reputation_loader_uses_highest_value_when_aliases_collide() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trnm_rpc_market_reputation_alias_collision_{}_{}.json",
            std::process::id(),
            now_ms()
        ));
        fs::write(
            &path,
            "{\"worker-a\": 10, \" Worker-A \": 200, \"WORKER-B\": -7}",
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
                assert_eq!(rep.len(), 2);
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
    fn load_ingress_records_quarantines_malformed_lines_with_accounting() {
        let _guard = lock_env();
        let path = unique_tmp_path("ingress-quarantine", "jsonl");
        let quarantine = ingress_quarantine_file_for(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quarantine);
        std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

        fs::write(
            &path,
            r#"{"request_id":"req-1","task_id":10001,"channel":"telegram","user_id":"u1","session_id":"s1","text":"ok","idempotency_key":"k1","status":"open","created_at_unix_ms":1,"assigned_worker":null,"assigned_at_unix_ms":null,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}
not-json
"#,
        )
        .expect("write ingress fixture");

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
        assert_eq!(entries[0]["raw_line"], "not-json");
        assert_eq!(entries[0]["source_path"], path.display().to_string());

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
