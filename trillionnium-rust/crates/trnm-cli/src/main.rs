use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "trnm-cli", version, about = "Trillionnium Rust-native CLI")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Tx {
        #[command(subcommand)]
        cmd: TxCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TxCommand {
    CommitResult {
        task_id: u64,
        worker: String,
        commit_hash: String,
        nonce: u64,
    },
    RevealResult {
        task_id: u64,
        result_hash: String,
        salt_hex: String,
    },
}

fn digest(parts: &[String]) -> String {
    let payload = parts.join("|");
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    format!("{:x}", h.finalize())
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Tx { cmd } => match cmd {
            TxCommand::CommitResult {
                task_id,
                worker,
                commit_hash,
                nonce,
            } => {
                let tx_hash = digest(&[
                    "commit-result".to_string(),
                    task_id.to_string(),
                    worker,
                    commit_hash,
                    nonce.to_string(),
                ]);
                println!("tx_hash={}", tx_hash);
            }
            TxCommand::RevealResult {
                task_id,
                result_hash,
                salt_hex,
            } => {
                let tx_hash = digest(&[
                    "reveal-result".to_string(),
                    task_id.to_string(),
                    result_hash,
                    salt_hex,
                ]);
                println!("tx_hash={}", tx_hash);
            }
        },
    }
    Ok(())
}
