use anyhow::Result;
use clap::Parser;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::time::{Duration, Instant};
#[cfg(test)]
use std::{fs, io::Write};
use trnm_rpc::{EventQueryResponse, MessageRequestQueryResponse, RequestFullQueryResponse};
#[cfg(test)]
use trnm_types::IdentityRegistry;
#[cfg(test)]
use trnm_types::RequestStatus;
#[cfg(test)]
use trnm_types::{TaskMetadata, TaskMeteringSnapshot, TaskObject, TaskStatus};

mod account_tx;
mod capability;
mod cli;
mod dispatch;
mod envpaths;
mod fsutil;
mod health;
mod http;
mod ingress;
mod ingress_flow;
mod market_flow;
mod market_io;
mod market_score;
mod metering;
mod node_events;
mod persistence;
mod read_query;
mod request_query;
mod rpc_util;
mod runtime;
mod shared;
mod snapshot;
mod taskview;
mod treasury;
mod validate;

#[cfg(test)]
use crate::account_tx::{
    FAUCET_MAX_REQUESTS_DEFAULT, FAUCET_MAX_REQUESTS_MIN, FAUCET_WINDOW_SECONDS_DEFAULT,
    FAUCET_WINDOW_SECONDS_MIN,
};
use crate::cli::Args;
use crate::dispatch::dispatch_command;
#[cfg(test)]
use crate::capability::resolve_capability_token_subject_or_token;
#[cfg(test)]
use crate::envpaths::{
    account_state_file, env_u32_with_min, env_u64_with_min, faucet_limits_file, ingress_file,
    market_bids_file, market_tasks_file, tx_lifecycle_file,
};
#[cfg(test)]
use crate::envpaths::{market_lock_timeout_ms, market_reputation_file, task_state_file};
#[cfg(test)]
use crate::envpaths::{normalized_path_from_env, run_root};
#[cfg(test)]
use crate::fsutil::atomic_write_text_file;
#[cfg(test)]
use crate::http::{
    configure_health_stream, parse_http_get_path, parse_query_events_limit_from_path,
    read_http_request_head,
};
#[cfg(test)]
use crate::ingress::ingress_quarantine_file_for;
#[cfg(test)]
use crate::ingress::{is_same_submit_message_idempotency_scope, load_ingress_records};
#[cfg(test)]
use crate::market_io::market_lock_path;
#[cfg(test)]
use crate::market_io::{
    acquire_market_file_lock, load_market_reputation, market_worker_tie_break_key,
    normalize_market_status_key, normalize_market_worker_key,
};
#[cfg(test)]
use crate::market_score::{market_effective_score, market_score_config};
#[cfg(test)]
use crate::metering::{
    parse_event_log_kv, parse_i128_kv_value, parse_u128_kv_value, parse_u64_kv_value,
};
#[cfg(test)]
use crate::node_events::{
    discover_default_node_event_log_sources, load_latest_node_events, load_node_event_log_sources,
    load_node_events_from_root, read_log_tail,
};
#[cfg(test)]
use crate::ingress_flow::{DISPATCH_OPEN_LIMIT_DEFAULT, DISPATCH_OPEN_LIMIT_MAX};
#[cfg(test)]
use crate::rpc_util::{clamp_limit, resolve_ops_window};
#[cfg(test)]
use crate::runtime::make_request_id;
#[cfg(test)]
use crate::runtime::now_ms;
pub(crate) use crate::shared::{
    normalize_actor_or_signer, normalize_tx_hash_lookup, push_tail_limited, AdapterRecord,
    IngressQuarantineRecord, LoadedNodeEvents, MarketBid, MarketTask, MessageIngressRecord,
    NodeEventRecord, NodeEventScanMode, OpsWindowArg,
};
pub(crate) use crate::shared::is_hex_like_tx_hash;
#[cfg(test)]
use crate::snapshot::query_task_from_state_snapshot;
#[cfg(test)]
use crate::snapshot::{governance_state, load_latest_adapter_records};
#[cfg(test)]
use crate::taskview::query_task_from_node_events;
#[cfg(test)]
use crate::taskview::query_events_response;
#[cfg(test)]
use crate::treasury::summarize_challenge_treasury;
#[cfg(test)]
use crate::validate::transition_request_status;

const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
const QUERY_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
const QUERY_FULL_LIMIT_MAX: usize = 200;
#[cfg(test)]
const NODE_EVENT_LOG_TAIL_BYTES_DEFAULT: u64 = 4 * 1024 * 1024;
#[cfg(test)]
const NODE_EVENT_LOG_TAIL_BYTES_MAX: u64 = 16 * 1024 * 1024;
const NODE_EVENT_LOG_SOURCES_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_SOURCES";
const NODE_EVENT_LOG_MANIFEST_ENV: &str = "TRNM_RPC_NODE_EVENT_LOG_MANIFEST";
const OPS_WINDOW_CUSTOM_MAX_MS: u128 = 31 * 24 * 60 * 60 * 1000;
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

fn main() -> Result<()> {
    let args = Args::parse();
    dispatch_command(args.cmd)
}

#[cfg(test)]
mod tests;
