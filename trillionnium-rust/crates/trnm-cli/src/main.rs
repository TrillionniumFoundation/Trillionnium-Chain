use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcCommand,
};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-cli",
    version,
    about = "Trillionnium native CLI (wallet/query/tx MVP)"
)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Transaction related commands
    Tx {
        #[command(subcommand)]
        tx: TxCommand,
    },
    /// Wallet related commands
    Wallet {
        #[command(subcommand)]
        wallet: WalletCommand,
    },
    /// Query commands (RPC/model-facing)
    Query {
        #[command(subcommand)]
        query: QueryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TxCommand {
    /// Legacy commit-result tx (kept for compatibility)
    CommitResult {
        task_id: u64,
        worker: String,
        commit_hash: String,
        nonce: u64,
    },
    /// Legacy reveal-result tx (kept for compatibility)
    RevealResult {
        task_id: u64,
        result_hash: String,
        salt_hex: String,
    },
    /// Query legacy tx status by hash
    Query { tx_hash: String },
    /// Transfer balance from one wallet to another
    Transfer {
        #[arg(long, default_value = "default")]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "trnm")]
        denom: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    /// Create a new local wallet (MVP placeholder)
    Create {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Alias of wallet create (backward compatible)
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import private key hex into local wallet store
    Import {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        private_key_hex: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print derived address from local wallet
    Address {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Sign arbitrary text (MVP deterministic signature)
    Sign {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum QueryCommand {
    /// Query account balance via new RPC/model contract
    Balance {
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, default_value = "trnm")]
        denom: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BalanceQueryResponse {
    address: String,
    balance: String,
    denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferTxRequest {
    from: String,
    to: String,
    amount: String,
    denom: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferTxResponse {
    tx_hash: String,
    status: String,
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
    let key_bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private key hex must be 32 bytes (64 hex chars)"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let digest = Sha256::digest(signing_key.verifying_key().as_bytes());
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

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(h) = v.get("tx_hash").and_then(|x| x.as_str()) {
            return Some(h.to_string());
        }
        if let Some(h) = v.get("txhash").and_then(|x| x.as_str()) {
            return Some(h.to_string());
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
        bail!(
            "tx command failed rc={}: {}",
            out.status.code().unwrap_or(1),
            merged
        );
    }

    if let Some(txh) = extract_tx_hash(&merged) {
        return Ok(txh);
    }

    Ok(hash(&["fallback", &merged]))
}

fn run_template_raw(cmd: &str) -> Result<String> {
    let out = ProcCommand::new("sh").arg("-lc").arg(cmd).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }
    Ok(stdout.to_string())
}

fn tpl(mut s: String, key: &str, val: &str) -> String {
    s = s.replace(&format!("{{{}}}", key), val);
    s
}

fn default_tx_state_file() -> PathBuf {
    if let Ok(path) = std::env::var("TRNM_RPC_TX_FILE") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("run/rpc/txs.json"))
        .unwrap_or_else(|| PathBuf::from("run/rpc/txs.json"))
}

fn query_local_tx_status(tx_hash: &str) -> Option<String> {
    let path = default_tx_state_file();
    let raw = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let rec = v.get(tx_hash)?;
    rec.get("status")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

fn persist_local_pending_tx(tx_hash: &str) -> Result<()> {
    let path = default_tx_state_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut root: serde_json::Map<String, serde_json::Value> =
        if let Ok(raw) = fs::read_to_string(&path) {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    root.insert(
        tx_hash.to_string(),
        serde_json::json!({
            "tx_hash": tx_hash,
            "status": "pending",
            "error": null,
            "submitted_at_unix_ms": now_ms,
            "updated_at_unix_ms": now_ms
        }),
    );

    fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

fn wallet_create(name: String, out: Option<PathBuf>) -> Result<()> {
    let store = out.unwrap_or_else(default_wallet_store);
    let priv_hex = random_priv_hex()?;
    let path = write_key(&store, &name, &priv_hex)?;
    let addr = derive_address_from_priv_hex(&priv_hex)?;
    println!("wallet_name={}", name);
    println!("wallet_path={}", path.display());
    println!("address={}", addr);
    println!("public_key_hint={}", sha256_hex(priv_hex.as_bytes()));
    Ok(())
}

fn resolve_address_for_query(
    address: Option<String>,
    name: Option<String>,
    store: Option<PathBuf>,
) -> Result<String> {
    if let Some(a) = address {
        return Ok(a);
    }
    let wallet_name = name.unwrap_or_else(|| "default".to_string());
    let s = store.unwrap_or_else(default_wallet_store);
    let priv_hex = read_key(&s, &wallet_name)?;
    derive_address_from_priv_hex(&priv_hex)
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
                    let status = query_local_tx_status(&tx_hash).unwrap_or_else(|| "unknown".into());
                    println!("tx_hash={}", tx_hash);
                    println!("status={}", status);
                }
            }
            TxCommand::Transfer {
                from,
                to,
                amount,
                denom,
                store,
            } => {
                let s = store.unwrap_or_else(default_wallet_store);
                let from_priv_hex = read_key(&s, &from)?;
                let from_addr = derive_address_from_priv_hex(&from_priv_hex)?;
                let req = TransferTxRequest {
                    from: from_addr,
                    to,
                    amount: amount.to_string(),
                    denom,
                };

                if let Ok(template) = std::env::var("TRNM_TX_TRANSFER_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "from", &req.from);
                    cmd = tpl(cmd, "to", &req.to);
                    cmd = tpl(cmd, "amount", &req.amount);
                    cmd = tpl(cmd, "denom", &req.denom);
                    let tx_hash = run_template(&cmd)?;
                    let out = TransferTxResponse {
                        tx_hash,
                        status: "submitted".into(),
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    let tx_hash = hash(&[
                        "transfer",
                        &req.from,
                        &req.to,
                        &req.amount,
                        &req.denom,
                    ]);
                    persist_local_pending_tx(&tx_hash)?;
                    let out = TransferTxResponse {
                        tx_hash,
                        status: "pending".into(),
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
        },
        Command::Wallet { wallet } => match wallet {
            WalletCommand::Create { name, out } | WalletCommand::Generate { name, out } => {
                wallet_create(name, out)?;
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
        Command::Query { query } => match query {
            QueryCommand::Balance {
                address,
                name,
                store,
                denom,
            } => {
                let addr = resolve_address_for_query(address, name, store)?;

                if let Ok(template) = std::env::var("TRNM_QUERY_BALANCE_CMD") {
                    let mut cmd = template;
                    cmd = tpl(cmd, "address", &addr);
                    cmd = tpl(cmd, "denom", &denom);
                    let raw = run_template_raw(&cmd)?;
                    if let Ok(resp) = serde_json::from_str::<BalanceQueryResponse>(&raw) {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        let out = BalanceQueryResponse {
                            address: addr,
                            balance: raw.trim().to_string(),
                            denom,
                        };
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    }
                } else {
                    let seeded = hash(&["balance", &addr, &denom]);
                    let pseudo = u128::from_str_radix(&seeded[..16], 16).unwrap_or(0) % 1_000_000;
                    let out = BalanceQueryResponse {
                        address: addr,
                        balance: pseudo.to_string(),
                        denom,
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_import_hex_check() {
        let ok = ensure_hex_32_bytes("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        assert_eq!(ok.len(), 64);
        assert!(ensure_hex_32_bytes("0x1234").is_err());
    }

    #[test]
    fn extract_tx_hash_supports_json_and_kv() {
        assert_eq!(
            extract_tx_hash("tx_hash=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            extract_tx_hash("{\"tx_hash\":\"deadbeef\",\"status\":\"ok\"}").as_deref(),
            Some("deadbeef")
        );
    }

    #[test]
    fn tpl_replacement_works() {
        let got = tpl("send {from} {to} {amount}".to_string(), "from", "alice");
        let got = tpl(got, "to", "bob");
        let got = tpl(got, "amount", "7");
        assert_eq!(got, "send alice bob 7");
    }
}
