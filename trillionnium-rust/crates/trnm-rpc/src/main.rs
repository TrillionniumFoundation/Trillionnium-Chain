use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_rpc::{
    get_tx, query_account_state, submit_tx, validate_trnm_address, AccountBalanceQueryResponse,
    AccountNonceQueryResponse, AccountState, EventQueryResponse, FaucetRequestResponse, GetTxError,
    GovParamQueryResponse, GovProposalQueryResponse, InMemoryTransferLedger,
    MessageRequestQueryResponse, RequestFullQueryResponse, RpcErrorResponse, TaskQueryResponse,
    TxLifecycleRecord,
};
use trnm_state::StateStore;
use trnm_types::{
    GovParamObject, GovProposalObject, GovProposalStatus, RequestStatus, TaskStatus, TransferTx,
};

const QUERY_EVENTS_LIMIT_DEFAULT: usize = 100;
const QUERY_EVENTS_LIMIT_MAX: usize = 500;
const QUERY_FULL_LIMIT_DEFAULT: usize = 50;
const QUERY_FULL_LIMIT_MAX: usize = 200;
const DISPATCH_OPEN_LIMIT_DEFAULT: usize = 20;
const DISPATCH_OPEN_LIMIT_MAX: usize = 100;

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

fn load_latest_node_events() -> Vec<NodeEventRecord> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        root.join("run/parallel-sanity.log"),
        root.join("run/node1.log"),
        root.join("run/node2.log"),
        root.join("run/node3.log"),
    ];

    let mut lines = Vec::new();
    for p in candidates {
        if let Ok(raw) = fs::read_to_string(&p) {
            lines.extend(raw.lines().map(str::to_string));
        }
    }

    let mut out = Vec::new();
    for line in lines {
        if !line.starts_with("[event]") || !line.contains("event_type=") {
            continue;
        }
        let mut kv = BTreeMap::<String, String>::new();
        for tok in line.split_whitespace().skip(1) {
            if let Some((k, v)) = tok.split_once('=') {
                kv.insert(k.to_string(), v.to_string());
            }
        }

        let Some(task_id) = kv.get("task_id").and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let Some(tx_id) = kv.get("tx_id").and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let Some(block_height) = kv.get("block_height").and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let ts_unix_ms = kv
            .get("ts_unix_ms")
            .and_then(|s| s.parse::<u128>().ok())
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
        });
    }
    out
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
    let _ = st.set_gov_param(7001, "max_block_ms".into(), "10".into());
    let _ = st.set_gov_param(7999, "emergency_pause".into(), "false".into());
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

fn make_request_id(
    channel: &str,
    user_id: &str,
    session_id: &str,
    idempotency_key: &str,
    ts: u128,
) -> String {
    let mut h = Sha256::new();
    h.update(
        format!(
            "{}|{}|{}|{}|{}",
            channel, user_id, session_id, idempotency_key, ts
        )
        .as_bytes(),
    );
    let digest = hex::encode(h.finalize());
    format!("req_{}", &digest[..16])
}

fn ingress_file() -> PathBuf {
    run_root().join("run/message-gateway/requests.jsonl")
}

fn load_ingress_records() -> Vec<MessageIngressRecord> {
    let path = ingress_file();
    let Ok(raw) = fs::read_to_string(path) else {
        return vec![];
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<MessageIngressRecord>(l).ok())
        .collect()
}

fn save_ingress_records(records: &[MessageIngressRecord]) -> Result<()> {
    let path = ingress_file();
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

fn account_state_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_ACCOUNTS_FILE") {
        return PathBuf::from(path);
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(accounts)?)?;
    Ok(())
}

fn tx_lifecycle_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_TX_FILE") {
        return PathBuf::from(path);
    }
    run_root().join("run/rpc/txs.json")
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FaucetRateEntry {
    window_start_unix_ms: u128,
    count_in_window: u32,
}

fn faucet_limits_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_FAUCET_LIMITS_FILE") {
        return PathBuf::from(path);
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(limits)?)?;
    Ok(())
}

fn load_tx_lifecycle(path: &Path) -> BTreeMap<String, TxLifecycleRecord> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str::<BTreeMap<String, TxLifecycleRecord>>(&raw).unwrap_or_default()
}

fn save_tx_lifecycle(path: &Path, txs: &BTreeMap<String, TxLifecycleRecord>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(txs)?)?;
    Ok(())
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

fn serve_health(host: &str, port: u16) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    eprintln!("[trnm-rpc] service listening on http://{addr}");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let first = req.lines().next().unwrap_or("");

        if first.starts_with("GET /health") {
            let body = serde_json::json!({
                "ok": true,
                "service": "trnm-rpc",
                "ts_unix_ms": now_ms(),
                "version": 1
            })
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        } else {
            let body = "{\"ok\":false,\"code\":\"NOT_FOUND\"}";
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let st = governance_state();
    let recs = load_latest_adapter_records();
    let node_events = load_latest_node_events();

    match args.cmd {
        Command::QueryTask { task_id } => {
            let node_task_events: Vec<&NodeEventRecord> = node_events
                .iter()
                .filter(|e| e.task_id == task_id)
                .collect();
            if !node_task_events.is_empty() {
                let latest = node_task_events.last().unwrap();
                let status = match latest.to_status.as_str() {
                    "Open" => TaskStatus::Open,
                    "Assigned" => TaskStatus::Assigned,
                    "Committed" => TaskStatus::Committed,
                    "Revealed" => TaskStatus::Revealed,
                    "Challenged" => TaskStatus::Challenged,
                    "Completed" => TaskStatus::Completed,
                    "Slashed" => TaskStatus::Slashed,
                    _ => TaskStatus::Open,
                };
                let out = TaskQueryResponse {
                    task_id,
                    status,
                    worker: node_task_events
                        .iter()
                        .rev()
                        .find(|e| {
                            e.event_type == "accept"
                                || e.event_type == "commit"
                                || e.event_type == "reveal"
                        })
                        .map(|e| e.actor.clone()),
                    bounty: 100,
                    result_hash_hex: None,
                    version: node_task_events.len() as u64,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }

            let task_recs: Vec<&AdapterRecord> = recs
                .iter()
                .filter(|r| r.task_id == task_id && r.status == "accepted")
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
            let out = TaskQueryResponse {
                task_id,
                status,
                worker,
                bounty: 100,
                result_hash_hex,
                version: task_recs.len() as u64,
            };
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
            let limit = clamp_limit(
                "QueryEvents",
                limit,
                QUERY_EVENTS_LIMIT_DEFAULT,
                QUERY_EVENTS_LIMIT_MAX,
            );
            let mut events = Vec::new();

            for e in node_events.iter().filter(|e| e.task_id == task_id) {
                events.push(EventQueryResponse {
                    event_type: e.event_type.clone(),
                    task_id,
                    from_status: e.from_status.clone(),
                    to_status: e.to_status.clone(),
                    actor: e.actor.clone(),
                    tx_id: e.tx_id,
                    block_height: e.block_height,
                    state_root: e.state_root.clone(),
                    ts_unix_ms: e.ts_unix_ms,
                    signer: e.signer.clone().or_else(|| Some(e.actor.clone())),
                    challenger: e.challenger.clone(),
                    tx_hash: e.tx_hash.clone(),
                    resolution_code: e.resolution_code.clone(),
                });
            }

            if events.is_empty() {
                let mut tx_id = 1u64;
                for r in recs
                    .into_iter()
                    .filter(|r| r.task_id == task_id && r.status == "accepted")
                {
                    let (from_status, to_status, actor) = if r.kind == "commit" {
                        (
                            "Assigned".to_string(),
                            "Committed".to_string(),
                            r.worker.clone().unwrap_or_else(|| "worker".into()),
                        )
                    } else {
                        (
                            "Committed".to_string(),
                            "Revealed".to_string(),
                            "worker".to_string(),
                        )
                    };
                    let signer = Some(actor.clone());
                    let tx_hash = r.tx_hash;
                    events.push(EventQueryResponse {
                        event_type: r.kind,
                        task_id,
                        from_status,
                        to_status,
                        actor,
                        tx_id,
                        block_height: tx_id,
                        state_root: "adapter_state".into(),
                        ts_unix_ms: r.ts as u128,
                        signer,
                        challenger: None,
                        tx_hash,
                        resolution_code: None,
                    });
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
            println!("{}", serde_json::to_string_pretty(&events)?);
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
            let mut txs = load_tx_lifecycle(&tx_path);

            let account_path = account_state_file();
            let mut accounts = load_account_state(&account_path);
            let mut ledger = accounts_to_ledger(&accounts);

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
            let window_seconds = std::env::var("TRNM_RPC_FAUCET_WINDOW_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);
            let max_requests_in_window = std::env::var("TRNM_RPC_FAUCET_MAX_REQUESTS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(1);
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
            let records = load_ingress_records();
            if let Some(found) = records
                .iter()
                .find(|r| r.idempotency_key == idempotency_key && r.session_id == session_id)
            {
                println!("{}", serde_json::to_string_pretty(found)?);
                return Ok(());
            }

            let ts = now_ms();
            let request_id = make_request_id(&channel, &user_id, &session_id, &idempotency_key, ts);
            let task_id = 10_000 + records.len() as u64 + 1;
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

            let path = ingress_file();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut buf = String::new();
            if let Ok(existing) = fs::read_to_string(&path) {
                buf.push_str(&existing);
                if !existing.ends_with('\n') {
                    buf.push('\n');
                }
            }
            buf.push_str(&serde_json::to_string(&rec)?);
            buf.push('\n');
            fs::write(&path, buf)?;

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

            let mut events = Vec::new();
            for e in node_events.iter().filter(|e| e.task_id == rec.task_id) {
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
                    actor: e.actor.clone(),
                    tx_id: e.tx_id,
                    block_height: e.block_height,
                    state_root: e.state_root.clone(),
                    ts_unix_ms: e.ts_unix_ms,
                    signer: e.signer.clone().or_else(|| Some(e.actor.clone())),
                    challenger: e.challenger.clone(),
                    tx_hash,
                    resolution_code,
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
        Command::DispatchOpen { worker_id, limit } => {
            let limit = clamp_limit(
                "DispatchOpen",
                limit,
                DISPATCH_OPEN_LIMIT_DEFAULT,
                DISPATCH_OPEN_LIMIT_MAX,
            );
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
}
