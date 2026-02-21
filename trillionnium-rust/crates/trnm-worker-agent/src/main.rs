use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Debug, Parser)]
#[command(name = "trnm-worker-agent", version, about = "Trillionnium PoUW worker-agent (MVP skeleton)")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
    },
    RunOnce {
        #[arg(long, default_value = "worker-state.json")]
        state: PathBuf,
        #[arg(long)]
        worker: String,
        #[arg(long, default_value = "demo-result")]
        payload: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerState {
    last_task_id: u64,
}

#[derive(Debug, Serialize)]
struct RunOnceOutput {
    task_id: u64,
    worker: String,
    result_hash: String,
    salt_hex: String,
    commit_hash: String,
    template_commit: String,
    template_reveal: String,
}

fn commitment(task_id: u64, result_hash_hex: &str, salt_hex: &str, worker: &str) -> String {
    let payload = format!("{}|{}|{}|{}", task_id, result_hash_hex, salt_hex, worker);
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

fn next_task_id(state: &PathBuf) -> Result<u64> {
    let mut s = if state.exists() {
        serde_json::from_str::<WorkerState>(&fs::read_to_string(state)?)?
    } else {
        WorkerState { last_task_id: 1000 }
    };
    s.last_task_id += 1;
    fs::write(state, serde_json::to_string_pretty(&s)?)?;
    Ok(s.last_task_id)
}

fn execute_payload(payload: &str, task_id: u64) -> (String, String) {
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    let result_hash = hex::encode(h.finalize());
    let salt_hex = format!("{:064x}", task_id);
    (result_hash, salt_hex)
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::PullTask { state } => {
            let task_id = next_task_id(&state)?;
            println!("[agent] pulled task_id={}", task_id);
        }
        Command::Execute {
            task_id,
            worker,
            payload,
        } => {
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            println!("[agent] executed task_id={} worker={}", task_id, worker);
            println!("result_hash={}", result_hash);
            println!("salt_hex={}", salt_hex);
        }
        Command::CommitReveal {
            task_id,
            worker,
            result_hash,
            salt_hex,
        } => {
            let c = commitment(task_id, &result_hash, &salt_hex, &worker);
            println!("[agent] task_id={} worker={}", task_id, worker);
            println!("commit_hash={}", c);
            println!(
                "template_commit=trnm-node tx commit-result {} {} {}",
                task_id, worker, c
            );
            println!(
                "template_reveal=trnm-node tx reveal-result {} {} {}",
                task_id, result_hash, salt_hex
            );
        }
        Command::RunOnce {
            state,
            worker,
            payload,
        } => {
            let task_id = next_task_id(&state)?;
            let (result_hash, salt_hex) = execute_payload(&payload, task_id);
            let commit_hash = commitment(task_id, &result_hash, &salt_hex, &worker);
            let out = RunOnceOutput {
                task_id,
                worker: worker.clone(),
                result_hash: result_hash.clone(),
                salt_hex: salt_hex.clone(),
                commit_hash: commit_hash.clone(),
                template_commit: format!(
                    "trnm-node tx commit-result {} {} {}",
                    task_id, worker, commit_hash
                ),
                template_reveal: format!(
                    "trnm-node tx reveal-result {} {} {}",
                    task_id, result_hash, salt_hex
                ),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}
