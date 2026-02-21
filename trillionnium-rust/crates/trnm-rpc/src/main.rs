use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{fs, path::PathBuf};
use trnm_rpc::{EventQueryResponse, GovParamQueryResponse, GovProposalQueryResponse, TaskQueryResponse};
use trnm_state::StateStore;
use trnm_types::{GovParamObject, GovProposalObject, GovProposalStatus, TaskStatus};

#[derive(Debug, Parser)]
#[command(name = "trnm-rpc", version, about = "Trillionnium RPC (state-backed query schema)")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    QueryTask { task_id: u64 },
    QueryProposal { proposal_id: u64 },
    QueryParam { key: String },
    QueryEvents { task_id: u64 },
}

#[derive(Debug, Clone, Deserialize)]
struct AdapterRecord {
    ts: u64,
    kind: String,
    task_id: u64,
    worker: Option<String>,
    result_hash: Option<String>,
    status: String,
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
        .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl")).unwrap_or(false))
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

fn main() -> Result<()> {
    let args = Args::parse();
    let st = governance_state();
    let recs = load_latest_adapter_records();

    match args.cmd {
        Command::QueryTask { task_id } => {
            let task_recs: Vec<&AdapterRecord> = recs.iter().filter(|r| r.task_id == task_id && r.status == "accepted").collect();
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
            let result_hash_hex = task_recs
                .iter()
                .rev()
                .find_map(|r| if r.kind == "reveal" { r.result_hash.clone() } else { None });
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
        Command::QueryEvents { task_id } => {
            let mut tx_id = 1u64;
            let mut events = Vec::new();
            for r in recs.into_iter().filter(|r| r.task_id == task_id && r.status == "accepted") {
                let (from_status, to_status, actor) = if r.kind == "commit" {
                    ("Assigned".to_string(), "Committed".to_string(), r.worker.clone().unwrap_or_else(|| "worker".into()))
                } else {
                    ("Committed".to_string(), "Revealed".to_string(), "worker".to_string())
                };
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
                });
                tx_id += 1;
            }
            if events.is_empty() {
                bail!("events not found for task_id={}", task_id);
            }
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
    }

    Ok(())
}
