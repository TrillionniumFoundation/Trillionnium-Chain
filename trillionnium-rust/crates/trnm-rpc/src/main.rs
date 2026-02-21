use clap::{Parser, Subcommand};
use trnm_rpc::{EventQueryResponse, GovParamQueryResponse, GovProposalQueryResponse, TaskQueryResponse};
use trnm_types::{GovProposalStatus, TaskStatus};

#[derive(Debug, Parser)]
#[command(name = "trnm-rpc", version, about = "Trillionnium RPC mock (stable query schema)")]
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

fn main() {
    let args = Args::parse();
    match args.cmd {
        Command::QueryTask { task_id } => {
            let out = TaskQueryResponse {
                task_id,
                status: TaskStatus::Open,
                worker: None,
                bounty: 100,
                result_hash_hex: None,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::QueryProposal { proposal_id } => {
            let out = GovProposalQueryResponse {
                proposal_id,
                title: "update max_block_ms".into(),
                proposer: "alice".into(),
                status: GovProposalStatus::Voting,
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::QueryParam { key } => {
            let out = GovParamQueryResponse {
                key,
                value: "10".into(),
                version: 1,
            };
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::QueryEvents { task_id } => {
            let out = vec![EventQueryResponse {
                event_type: "create".into(),
                task_id,
                from_status: "NONE".into(),
                to_status: "Open".into(),
                actor: "alice".into(),
                tx_id: 1,
                block_height: 1,
                state_root: "dummy_root".into(),
                ts_unix_ms: 0,
            }];
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
    }
}
