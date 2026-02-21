use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use trnm_rpc::{EventQueryResponse, GovParamQueryResponse, GovProposalQueryResponse, TaskQueryResponse};
use trnm_state::StateStore;
use trnm_types::{GovParamObject, GovProposalObject, GovProposalStatus, TaskObject, TaskStatus};

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

fn demo_state() -> StateStore {
    let mut st = StateStore::new();

    let _ = st.put_task_new(TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Revealed,
        worker: Some("worker1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        version: 1,
    });

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
    let st = demo_state();

    match args.cmd {
        Command::QueryTask { task_id } => {
            let Some(t) = st.get_task(task_id) else {
                bail!("task not found: {}", task_id);
            };
            let out = TaskQueryResponse {
                task_id: t.task_id,
                status: t.status,
                worker: t.worker,
                bounty: t.bounty,
                result_hash_hex: t.result_hash.map(hex::encode),
                version: t.version,
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
            let events = vec![
                EventQueryResponse {
                    event_type: "create".into(),
                    task_id,
                    from_status: "NONE".into(),
                    to_status: "Open".into(),
                    actor: "alice".into(),
                    tx_id: 1,
                    block_height: 1,
                    state_root: "demo_root_1".into(),
                    ts_unix_ms: 1,
                },
                EventQueryResponse {
                    event_type: "accept".into(),
                    task_id,
                    from_status: "Open".into(),
                    to_status: "Assigned".into(),
                    actor: "worker1".into(),
                    tx_id: 2,
                    block_height: 1,
                    state_root: "demo_root_2".into(),
                    ts_unix_ms: 2,
                },
                EventQueryResponse {
                    event_type: "reveal".into(),
                    task_id,
                    from_status: "Committed".into(),
                    to_status: "Revealed".into(),
                    actor: "worker1".into(),
                    tx_id: 4,
                    block_height: 2,
                    state_root: "demo_root_3".into(),
                    ts_unix_ms: 3,
                },
            ];
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
    }

    Ok(())
}
