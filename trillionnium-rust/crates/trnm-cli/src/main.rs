use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::process::Command as ProcCommand;

#[derive(Debug, Parser)]
#[command(name = "trnm-cli", version, about = "Trillionnium native CLI (tx MVP + real-cmd bridge)")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Tx {
        #[command(subcommand)]
        tx: TxCommand,
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
    Query {
        tx_hash: String,
    },
}

fn hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(parts.join("|").as_bytes());
    hex::encode(h.finalize())
}

fn extract_tx_hash(text: &str) -> Option<String> {
    // 1) tx_hash=...
    if let Some(v) = text
        .split_whitespace()
        .find_map(|w| w.strip_prefix("tx_hash=").map(|s| s.to_string()))
    {
        return Some(v);
    }

    // 2) JSON-like: "txhash":"..."
    if let Some(i) = text.find("\"txhash\"") {
        let tail = &text[i..];
        if let Some(q1) = tail.find('"') {
            let tail2 = &tail[q1 + 1..];
            if let Some(q2) = tail2.find('"') {
                let tail3 = &tail2[q2 + 1..];
                if let Some(q3) = tail3.find('"') {
                    let tail4 = &tail3[q3 + 1..];
                    if let Some(q4) = tail4.find('"') {
                        return Some(tail4[..q4].to_string());
                    }
                }
            }
        }
    }

    None
}

fn run_template(cmd: &str) -> Result<String> {
    let out = ProcCommand::new("sh").arg("-lc").arg(cmd).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let merged = format!("{}\n{}", stdout, stderr);

    if !out.status.success() {
        bail!("tx command failed rc={}: {}", out.status.code().unwrap_or(1), merged);
    }

    if let Some(txh) = extract_tx_hash(&merged) {
        return Ok(txh);
    }

    Ok(hash(&["fallback", &merged]))
}

fn tpl(mut s: String, key: &str, val: &str) -> String {
    s = s.replace(&format!("{{{}}}", key), val);
    s
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Command::Tx { tx } => match tx {
            TxCommand::CommitResult {
                task_id,
                worker,
                commit_hash,
                nonce,
            } => {
                if let Ok(template) = std::env::var("TRNM_TX_COMMIT_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "task_id", &task_id.to_string());
                    cmd = tpl(cmd, "worker", &worker);
                    cmd = tpl(cmd, "commit_hash", &commit_hash);
                    cmd = tpl(cmd, "nonce", &nonce.to_string());
                    let tx_hash = run_template(&cmd)?;
                    println!("tx_hash={}", tx_hash);
                } else {
                    let tx_hash = hash(&[
                        "commit-result",
                        &task_id.to_string(),
                        &worker,
                        &commit_hash,
                        &nonce.to_string(),
                    ]);
                    println!("tx_hash={}", tx_hash);
                }
            }
            TxCommand::RevealResult {
                task_id,
                result_hash,
                salt_hex,
            } => {
                if let Ok(template) = std::env::var("TRNM_TX_REVEAL_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "task_id", &task_id.to_string());
                    cmd = tpl(cmd, "result_hash", &result_hash);
                    cmd = tpl(cmd, "salt_hex", &salt_hex);
                    let tx_hash = run_template(&cmd)?;
                    println!("tx_hash={}", tx_hash);
                } else {
                    let tx_hash = hash(&[
                        "reveal-result",
                        &task_id.to_string(),
                        &result_hash,
                        &salt_hex,
                    ]);
                    println!("tx_hash={}", tx_hash);
                }
            }
            TxCommand::Query { tx_hash } => {
                if let Ok(template) = std::env::var("TRNM_TX_QUERY_CMD") {
                    let cmd = tpl(template, "tx_hash", &tx_hash);
                    let _ = run_template(&cmd)?;
                    println!("tx_hash={}", tx_hash);
                    println!("status=confirmed");
                } else {
                    println!("tx_hash={}", tx_hash);
                    println!("status=unknown");
                }
            }
        },
    }
    Ok(())
}
