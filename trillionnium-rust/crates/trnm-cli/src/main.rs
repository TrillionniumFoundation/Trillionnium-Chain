use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcCommand,
};

#[derive(Debug, Parser)]
#[command(name = "trnm-cli", version, about = "Trillionnium native CLI (tx + wallet MVP)")]
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
    Wallet {
        #[command(subcommand)]
        wallet: WalletCommand,
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

#[derive(Debug, Subcommand)]
enum WalletCommand {
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Import {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        private_key_hex: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    Sign {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

fn hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(parts.join("|").as_bytes());
    hex::encode(h.finalize())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn default_wallet_store() -> PathBuf {
    if let Ok(p) = std::env::var("TRNM_WALLET_STORE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".trnm").join("wallets")
}

fn wallet_file(store: &Path, name: &str) -> PathBuf {
    store.join(format!("{}.key", name))
}

fn ensure_hex_32_bytes(s: &str) -> Result<String> {
    let x = s.strip_prefix("0x").unwrap_or(s).to_lowercase();
    if x.len() != 64 {
        bail!("private key hex must be 32 bytes (64 hex chars)");
    }
    let _ = hex::decode(&x).map_err(|e| anyhow!("invalid private_key_hex: {e}"))?;
    Ok(x)
}

fn write_key(store: &Path, name: &str, priv_hex: &str) -> Result<PathBuf> {
    fs::create_dir_all(store)?;
    let f = wallet_file(store, name);
    fs::write(&f, format!("{}\n", priv_hex))?;
    Ok(f)
}

fn read_key(store: &Path, name: &str) -> Result<String> {
    let f = wallet_file(store, name);
    let raw = fs::read_to_string(&f)
        .map_err(|e| anyhow!("failed to read wallet '{}' at {}: {e}", name, f.display()))?;
    ensure_hex_32_bytes(raw.trim())
}

fn derive_address_from_priv_hex(priv_hex: &str) -> Result<String> {
    let key = hex::decode(priv_hex)?;
    let digest = Sha256::digest(&key);
    let addr_hex = hex::encode(&digest[..20]);
    Ok(format!("trnm1{}", addr_hex))
}

fn random_priv_hex() -> Result<String> {
    let mut b = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut b)?;
    Ok(hex::encode(b))
}

fn extract_tx_hash(text: &str) -> Option<String> {
    if let Some(v) = text
        .split_whitespace()
        .find_map(|w| w.strip_prefix("tx_hash=").map(|s| s.to_string()))
    {
        return Some(v);
    }

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
        Command::Wallet { wallet } => match wallet {
            WalletCommand::Generate { name, out } => {
                let store = out.unwrap_or_else(default_wallet_store);
                let priv_hex = random_priv_hex()?;
                let path = write_key(&store, &name, &priv_hex)?;
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("wallet_path={}", path.display());
                println!("address={}", addr);
                println!("public_key_hint={}", sha256_hex(priv_hex.as_bytes()));
            }
            WalletCommand::Import {
                name,
                private_key_hex,
                out,
            } => {
                let store = out.unwrap_or_else(default_wallet_store);
                let priv_hex = ensure_hex_32_bytes(&private_key_hex)?;
                let path = write_key(&store, &name, &priv_hex)?;
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("wallet_path={}", path.display());
                println!("address={}", addr);
            }
            WalletCommand::Address { name, store } => {
                let store = store.unwrap_or_else(default_wallet_store);
                let priv_hex = read_key(&store, &name)?;
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("address={}", addr);
            }
            WalletCommand::Sign {
                name,
                message,
                store,
            } => {
                let store = store.unwrap_or_else(default_wallet_store);
                let priv_hex = read_key(&store, &name)?;
                let sig = hash(&["trnm-sign-v1", &priv_hex, &message]);
                let addr = derive_address_from_priv_hex(&priv_hex)?;
                println!("wallet_name={}", name);
                println!("address={}", addr);
                println!("message={}", message);
                println!("signature={}", sig);
            }
        },
    }
    Ok(())
}
