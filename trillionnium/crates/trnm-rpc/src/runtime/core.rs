use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::io::{Seek, SeekFrom};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
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
    AuditEvent, CapabilityToken, GovParamObject, GovProposalObject, GovProposalStatus,
    IdentityRegistry, PrivacyTier, RequestStatus, TaskMetadata, TaskMeteringSnapshot, TaskObject,
    TaskStatus, TransferTx,
};

mod env;
pub(crate) use env::*;

mod governance;
pub(crate) use governance::*;

mod http;
pub(crate) use http::*;

mod market_lock;
pub(crate) use market_lock::*;

mod state_sync;
pub(crate) use state_sync::*;

mod dispatch_loop;
pub(crate) use dispatch_loop::*;

mod market_score;
pub(crate) use market_score::*;

mod audit_query;
pub(crate) use audit_query::*;

mod challenge_treasury;
pub(crate) use challenge_treasury::*;

mod task_query;
pub(crate) use task_query::*;

mod event_query;
pub(crate) use event_query::*;

#[path = "core/market_io.rs"]
mod market_io;
pub(crate) use market_io::*;

#[path = "core/metering.rs"]
mod metering;
pub(crate) use metering::*;

#[path = "core/node_events.rs"]
mod node_events;
pub(crate) use node_events::*;

#[path = "core/paths_state.rs"]
mod paths_state;
pub(crate) use paths_state::*;

#[path = "core/storage.rs"]
mod storage;
pub(crate) use storage::*;

pub(crate) const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
pub(crate) const QUERY_EVENTS_LIMIT_MAX: usize = 500;
pub(crate) const QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT: usize = 60;
pub(crate) const QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX: usize = 500;
pub(crate) const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
pub(crate) const QUERY_FULL_LIMIT_MAX: usize = 200;
pub(crate) const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
pub(crate) const DISPATCH_OPEN_LIMIT_MAX: usize = 100;
pub(crate) const CHALLENGE_TREASURY_EVENTS_LIMIT_DEFAULT: usize = 20;
pub(crate) const CHALLENGE_TREASURY_EVENTS_LIMIT_MAX: usize = 200;
pub(crate) const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
pub(crate) const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
#[cfg(test)]
pub(crate) const NODE_EVENT_LOG_TAIL_BYTES_DEFAULT: u64 = 4 * 1024 * 1024;
#[cfg(test)]
pub(crate) const NODE_EVENT_LOG_TAIL_BYTES_MAX: u64 = 16 * 1024 * 1024;
pub(crate) const NODE_EVENT_LOG_SOURCES_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_SOURCES";
pub(crate) const NODE_EVENT_LOG_MANIFEST_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_MANIFEST";
pub(crate) const OPS_WINDOW_CUSTOM_MAX_MS: u128 = 31 * 24 * 60 * 60 * 1000;
pub(crate) const FAUCET_WINDOW_SECONDS_DEFAULT: u64 = 60;
pub(crate) const FAUCET_WINDOW_SECONDS_MIN: u64 = 1;
pub(crate) const FAUCET_MAX_REQUESTS_DEFAULT: u32 = 1;
pub(crate) const FAUCET_MAX_REQUESTS_MIN: u32 = 1;
pub(crate) const EMERGENCY_PAUSE_KEY_ID: u64 = 7_999;
pub(crate) const MARKET_REPUTATION_FILE_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_FILE";
pub(crate) const TASK_STATE_FILE_ENV: &str = "TRNM_RPC_TASK_STATE_FILE";
pub(crate) const MARKET_PRICE_WEIGHT_ENV: &str = "TRNM_RPC_MARKET_PRICE_WEIGHT";
pub(crate) const MARKET_REPUTATION_WEIGHT_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_WEIGHT";
pub(crate) const MARKET_REPUTATION_CLAMP_ENV: &str = "TRNM_RPC_MARKET_REPUTATION_CLAMP";
pub(crate) const MARKET_PRICE_WEIGHT_DEFAULT: u128 = 1_000;
pub(crate) const MARKET_REPUTATION_WEIGHT_DEFAULT: u128 = 100;
pub(crate) const MARKET_REPUTATION_CLAMP_DEFAULT: i64 = 1_000;
pub(crate) const MARKET_WEIGHT_MIN: u128 = 1;
pub(crate) const MARKET_WEIGHT_MAX: u128 = 1_000_000;
pub(crate) const MARKET_REPUTATION_CLAMP_MIN: i64 = 1;
pub(crate) const MARKET_REPUTATION_CLAMP_MAX: i64 = 1_000_000;
pub(crate) const MARKET_LOCK_TIMEOUT_MS_DEFAULT: u64 = 5_000;
pub(crate) const MARKET_LOCK_TIMEOUT_MS_MIN: u64 = 100;
pub(crate) const MARKET_LOCK_TIMEOUT_MS_MAX: u64 = 60_000;
pub(crate) const SUBMIT_MESSAGE_MAX_BYTES_ENV: &str = "TRNM_RPC_SUBMIT_MESSAGE_MAX_BYTES";
pub(crate) const SUBMIT_MESSAGE_MAX_BYTES_DEFAULT: u64 = 256 * 1024;
pub(crate) const HEALTH_SOCKET_READ_TIMEOUT_MS: u64 = 2_000;
pub(crate) const HEALTH_SOCKET_WRITE_TIMEOUT_MS: u64 = 2_000;
pub(crate) const HEALTH_REQUEST_HEADER_MAX_BYTES: usize = 4 * 1024;
pub(crate) const SUBMIT_MESSAGE_MAX_BYTES_MIN: u64 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-rpc",
    version,
    about = "Trillionnium RPC (state-backed query schema)"
)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
    pub(crate) ts: u64,
    pub(crate) kind: String,
    pub(crate) task_id: u64,
    pub(crate) worker: Option<String>,
    pub(crate) result_hash: Option<String>,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MarketTask {
    pub(crate) task_id: u64,
    pub(crate) creator: String,
    pub(crate) bounty: u128,
    pub(crate) description: String,
    pub(crate) status: String,
    pub(crate) created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MarketBid {
    pub(crate) task_id: u64,
    pub(crate) worker: String,
    pub(crate) price: u128,
    pub(crate) created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MarketReport {
    pub(crate) task_count: usize,
    pub(crate) open_task_count: usize,
    pub(crate) matched_task_count: usize,
    pub(crate) unmatched_task_count: usize,
    pub(crate) bid_count: usize,
    pub(crate) orphan_bid_count: usize,
    pub(crate) unique_bidder_count: usize,
    pub(crate) tasks_with_bids_count: usize,
    pub(crate) bid_coverage_rate: f64,
    pub(crate) avg_bids_per_task: f64,
    pub(crate) match_rate: f64,
    pub(crate) match_config: MarketScoreConfigOutput,
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

#[derive(Debug, Clone)]
pub(crate) struct QueryNormalizedAuditEventsQuery {
    pub(crate) source: Option<String>,
    pub(crate) event_type: Option<String>,
    pub(crate) cursor: Option<usize>,
    pub(crate) limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NormalizedAuditEvent {
    pub(crate) source: String,
    pub(crate) event_type: String,
    pub(crate) actor: Option<String>,
    pub(crate) object_id: Option<String>,
    pub(crate) related_id: Option<String>,
    pub(crate) amount: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) note: Option<String>,
    #[serde(rename = "checkedAt")]
    pub(crate) checked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueryNormalizedAuditEventsResponse {
    pub(crate) events: Vec<NormalizedAuditEvent>,
    #[serde(rename = "nextCursor", default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
    #[serde(rename = "hasMore", default, skip_serializing_if = "Option::is_none")]
    pub(crate) has_more: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) total: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryEventView {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) tx_id: u64,
    pub(crate) block_height: u64,
    pub(crate) ts_unix_ms: u128,
    pub(crate) challenger: Option<String>,
    pub(crate) bond_disposition: Option<String>,
    pub(crate) bond_amount: u128,
    pub(crate) escrow_delta: i128,
    pub(crate) forfeits_delta: u128,
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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeDailySummary {
    pub(crate) posted: usize,
    pub(crate) refunded: usize,
    pub(crate) forfeited: usize,
    pub(crate) unresolved: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeWindowView {
    pub(crate) mode: String,
    pub(crate) from_unix_ms: u128,
    pub(crate) to_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryAnomaly {
    pub(crate) event_type: String,
    pub(crate) task_id: u64,
    pub(crate) tx_id: u64,
    pub(crate) code: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ChallengeTreasuryQueryResponse {
    pub(crate) challenge_escrow_account: String,
    pub(crate) challenge_forfeits_account: String,
    pub(crate) current_escrow_balance: u128,
    pub(crate) current_forfeits_balance: u128,
    pub(crate) cumulative_forfeited: u128,
    pub(crate) events_total: usize,
    pub(crate) events: Vec<ChallengeTreasuryEventView>,
    pub(crate) anomaly_count: usize,
    pub(crate) anomalies: Vec<ChallengeTreasuryAnomaly>,
    pub(crate) daily_summary: Option<ChallengeDailySummary>,
    pub(crate) window: Option<ChallengeWindowView>,
    pub(crate) node_event_source_mode: String,
    pub(crate) node_event_log_truncated: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CapabilityAuditQueryResponse {
    pub(crate) token: CapabilityToken,
    pub(crate) owner_history: Vec<AuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CapabilityAuditQueryError {
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

    fn http_status(&self) -> &'static str {
        match self {
            Self::TokenNotFound(_) => "404 Not Found",
            Self::InvalidRegistryState { .. } => "422 Unprocessable Entity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct FaucetRateEntry {
    pub(crate) window_start_unix_ms: u128,
    pub(crate) count_in_window: u32,
}

