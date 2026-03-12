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
    thread,
    time::{Duration, Instant},
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
    /// Query tx lifecycle status by hash
    Query { tx_hash: String },
    /// Wait until tx reaches committed/fail lifecycle state
    Wait {
        tx_hash: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TxQueryResponse {
    tx_hash: String,
    status: String,
    error: Option<String>,
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

fn normalize_tx_hash(raw: &str) -> Option<String> {
    let mut cleaned = raw.to_string();

    loop {
        let before = cleaned.len();
        cleaned = cleaned
            .trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}')
            })
            .to_string();

        if cleaned.len() >= 2 {
            let q = cleaned.chars().next().unwrap();
            let last = cleaned.chars().last().unwrap();
            if (q == '"' || q == '\'' || q == '`') && q == last {
                cleaned = cleaned[1..cleaned.len() - 1].to_string();
                continue;
            }
            // Add check for mismatched quotes or remaining punctuation inside?
            // The test case has (`"0xBEEF42"`,)
            // parse_kv_line -> (`"0xBEEF42"`
            // normalize -> "0xBEEF42" (trims parens)
            // then quotes are stripped -> 0xBEEF42
            // Seems correct?
        }
        if cleaned.len() == before {
            break;
        }
    }

    cleaned = cleaned.to_ascii_lowercase();

    if cleaned.starts_with("0x") && cleaned.len() > 2 {
        let body = &cleaned[2..];
        if body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(cleaned);
        }
        return None;
    }

    // Some adapters emit tx_hash without 0x prefix. Accept only plausible
    // hex-like values to avoid false positives from generic words.
    let is_hex_like = cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex_like && cleaned.len() >= 6 {
        return Some(cleaned);
    }

    None
}

fn extract_tx_hash(text: &str) -> Option<String> {
    if let Some(v) = text.split_whitespace().find_map(|w| {
        let trimmed = w.trim_matches(|c: char| c.is_ascii_whitespace());
        let (k, v) = trimmed
            .split_once('=')
            .or_else(|| trimmed.split_once(':'))?;
        match k.trim().to_ascii_lowercase().as_str() {
            "tx_hash" | "txhash" | "transaction_hash" | "transactionhash" => normalize_tx_hash(v),
            _ => None,
        }
    }) {
        return Some(v);
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(h) = v.get("tx_hash").and_then(|x| x.as_str()) {
            return normalize_tx_hash(h);
        }
        if let Some(h) = v.get("txhash").and_then(|x| x.as_str()) {
            return normalize_tx_hash(h);
        }
        if let Some(h) = v.get("txHash").and_then(|x| x.as_str()) {
            return normalize_tx_hash(h);
        }
        if let Some(h) = v.get("transaction_hash").and_then(|x| x.as_str()) {
            return normalize_tx_hash(h);
        }
        if let Some(h) = v.get("transactionHash").and_then(|x| x.as_str()) {
            return normalize_tx_hash(h);
        }
    }

    None
}

fn parse_template_command(cmd: &str) -> Result<(String, Vec<String>)> {
    let parts = shell_words::split(cmd)
        .map_err(|e| anyhow!("invalid template command (shell-words parse failed): {e}"))?;
    let Some((program, args)) = parts.split_first() else {
        bail!("template command must not be empty");
    };
    Ok((program.clone(), args.to_vec()))
}

fn run_template(cmd: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
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
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
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

    let mut merged = stdout.to_string();
    merged.push_str(&stderr);
    Ok(merged)
}

fn parse_kv_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    if key.is_empty() {
        return None;
    }

    Some((key.to_ascii_lowercase(), value.to_string()))
}

fn parse_inline_kv_token(token: &str) -> Option<(String, String)> {
    let trimmed = token.trim_matches(|c: char| {
        c.is_ascii_whitespace() || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')')
    });
    let (key, value) = if let Some((k, v)) = trimmed.split_once('=') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = trimmed.split_once(':') {
        (k.trim(), v.trim())
    } else {
        return None;
    };

    if key.is_empty() || value.is_empty() {
        return None;
    }

    Some((
        key.to_ascii_lowercase(),
        value
            .trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')')
            })
            .trim_matches('"')
            .trim_matches('\'')
            .trim_matches('`')
            .to_string(),
    ))
}

fn normalize_tx_status(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_matches(|c: char| {
            c.is_ascii_whitespace()
                || matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':')
        })
        .trim_end_matches(|c: char| c.is_ascii_punctuation())
        .to_ascii_lowercase();
    match cleaned.as_str() {
        "pending" | "submitted" | "accepted" | "queued" | "broadcast" | "broadcasted"
        | "processing" | "in_progress" | "in-progress" | "inflight" | "in-flight" => {
            Some("pending".to_string())
        }
        "committed" | "confirmed" | "success" | "succeeded" | "ok" | "included"
        | "finalized" | "complete" | "completed" | "done" => {
            Some("committed".to_string())
        }
        "fail" | "failed" | "error" | "rejected" | "reverted" | "aborted" | "dropped"
        | "timeout" | "timed_out" | "timed-out" | "expired" => Some("fail".to_string()),
        _ => None,
    }
}

fn is_nullish_kv_value(raw: &str) -> bool {
    let cleaned = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .trim_end_matches(|c: char| c.is_ascii_punctuation())
        .to_ascii_lowercase();
    cleaned.is_empty() || cleaned == "null"
}

fn normalize_json_error(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => {
            if is_nullish_kv_value(s) {
                None
            } else {
                Some(s.to_string())
            }
        }
        other => Some(other.to_string()),
    }
}

fn normalize_json_status(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => normalize_tx_status(s),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|code| if code == 0 { "committed" } else { "fail" }.to_string()),
        serde_json::Value::Bool(b) => Some(if *b { "committed" } else { "fail" }.to_string()),
        _ => None,
    }
}

fn json_u64_at_path(value: &serde_json::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn infer_json_tx_status(value: &serde_json::Value) -> Option<String> {
    for path in [
        ["tx_result", "code"].as_slice(),
        ["deliver_tx", "code"].as_slice(),
        ["check_tx", "code"].as_slice(),
        ["code"].as_slice(),
    ] {
        if let Some(code) = json_u64_at_path(value, path) {
            return Some(if code == 0 { "committed" } else { "fail" }.to_string());
        }
    }
    None
}

fn infer_kv_tx_status(key: &str, value: &str) -> Option<String> {
    match key {
        "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
        | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
            let cleaned = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('`')
                .trim_end_matches(|c: char| c.is_ascii_punctuation());
            let code = cleaned.parse::<u64>().ok()?;
            Some(if code == 0 { "committed" } else { "fail" }.to_string())
        }
        _ => None,
    }
}

fn parse_tx_query_response(raw: &str, requested_tx_hash: &str) -> Result<TxQueryResponse> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let payload = v.get("result").unwrap_or(&v);
        let nested_tx_response = payload
            .get("tx_response")
            .or_else(|| payload.get("txResponse"))
            .or_else(|| payload.get("response").and_then(|r| r.get("tx_response")))
            .or_else(|| payload.get("response").and_then(|r| r.get("txResponse")));
        let primary = nested_tx_response.unwrap_or(payload);
        let raw_tx_hash = primary
            .get("tx_hash")
            .or_else(|| primary.get("txhash"))
            .or_else(|| primary.get("txHash"))
            .or_else(|| primary.get("transaction_hash"))
            .or_else(|| primary.get("transactionHash"))
            .or_else(|| payload.get("tx_hash"))
            .or_else(|| payload.get("txhash"))
            .or_else(|| payload.get("txHash"))
            .or_else(|| payload.get("transaction_hash"))
            .or_else(|| payload.get("transactionHash"))
            .and_then(|x| x.as_str());
        let tx_hash = match raw_tx_hash {
            Some(raw_hash) => normalize_tx_hash(raw_hash)
                .ok_or_else(|| anyhow!("invalid tx_hash field in tx query response"))?,
            None => normalize_tx_hash(requested_tx_hash)
                .unwrap_or_else(|| requested_tx_hash.to_string()),
        };
        let status = primary
            .get("status")
            .or_else(|| primary.get("tx_status"))
            .or_else(|| primary.get("txStatus"))
            .or_else(|| primary.get("transaction_status"))
            .or_else(|| primary.get("transactionStatus"))
            .or_else(|| primary.get("state"))
            .or_else(|| primary.get("tx_state"))
            .or_else(|| primary.get("txState"))
            .or_else(|| primary.get("transaction_state"))
            .or_else(|| primary.get("transactionState"))
            .or_else(|| payload.get("status"))
            .or_else(|| payload.get("tx_status"))
            .or_else(|| payload.get("txStatus"))
            .or_else(|| payload.get("transaction_status"))
            .or_else(|| payload.get("transactionStatus"))
            .or_else(|| payload.get("state"))
            .or_else(|| payload.get("tx_state"))
            .or_else(|| payload.get("txState"))
            .or_else(|| payload.get("transaction_state"))
            .or_else(|| payload.get("transactionState"))
            .and_then(normalize_json_status)
            .or_else(|| infer_json_tx_status(primary))
            .or_else(|| infer_json_tx_status(payload))
            .ok_or_else(|| anyhow!("missing/invalid status field in tx query response"))?;
        let error = primary
            .get("error")
            .or_else(|| primary.get("raw_log"))
            .or_else(|| primary.get("rawLog"))
            .or_else(|| primary.get("log"))
            .or_else(|| payload.get("error"))
            .or_else(|| payload.get("raw_log"))
            .or_else(|| payload.get("rawLog"))
            .or_else(|| payload.get("log"))
            .and_then(normalize_json_error);
        return Ok(TxQueryResponse {
            tx_hash,
            status,
            error,
        });
    }

    let mut tx_hash: Option<String> = None;
    let mut status: Option<String> = None;
    let mut error: Option<String> = None;
    for line in raw.lines() {
        let mut pairs = Vec::new();
        if let Some(pair) = parse_kv_line(line) {
            pairs.push(pair);
        }
        for token in line.split_whitespace() {
            if let Some(pair) = parse_inline_kv_token(token) {
                pairs.push(pair);
            }
        }

        for (key, value) in pairs {
            match key.as_str() {
                "tx_hash" | "txhash" | "transaction_hash" | "transactionhash" => {
                    match normalize_tx_hash(&value) {
                        Some(normalized) => tx_hash = Some(normalized),
                        None => bail!("invalid tx_hash field in tx query response"),
                    }
                }
                "status" | "tx_status" | "txstatus" | "transaction_status"
                | "transactionstatus" | "state" | "tx_state" | "txstate" | "transaction_state"
                | "transactionstate" => {
                    if let Some(normalized) = normalize_tx_status(&value) {
                        status = Some(normalized);
                    }
                }
                "code" | "tx_code" | "txcode" | "transaction_code" | "transactioncode"
                | "deliver_tx_code" | "delivertxcode" | "check_tx_code" | "checktxcode" => {
                    if status.is_none() {
                        status = infer_kv_tx_status(&key, &value);
                    }
                }
                "error" | "raw_log" | "rawlog" | "log" => {
                    // Manual quote trimming since parse_kv_line no longer does it aggressively
                    let cleaned = value.trim_matches(|c| matches!(c, '"' | '\'' | '`'));
                    if !is_nullish_kv_value(cleaned) {
                        match &error {
                            Some(existing) if existing.len() >= cleaned.len() => {}
                            _ => error = Some(cleaned.to_string()),
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(status) = status {
        return Ok(TxQueryResponse {
            tx_hash: tx_hash.unwrap_or_else(|| requested_tx_hash.to_string()),
            status,
            error,
        });
    }

    bail!("failed to parse tx query response: {}", raw.trim())
}

fn tx_query(tx_hash: &str) -> Result<TxQueryResponse> {
    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for query (expected hex-like tx hash)"))?;

    if let Some(status) = query_local_tx_status(&requested) {
        return Ok(TxQueryResponse {
            tx_hash: requested,
            status,
            error: None,
        });
    }

    if let Ok(template) = std::env::var("TRNM_TX_QUERY_CMD") {
        let cmd = tpl(template, "tx_hash", &requested);
        let raw = run_template_raw(&cmd)?;
        let parsed = parse_tx_query_response(&raw, &requested)?;
        if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
            if requested != got {
                bail!(
                    "tx query response hash mismatch: requested={}, got={}",
                    requested,
                    got
                );
            }
        }
        return Ok(parsed);
    }

    let rpc_workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cmd = format!("cargo run -q -p trnm-rpc -- get-tx --tx-hash {}", requested);
    match {
        let (program, args) = parse_template_command(&cmd)?;
        let out = ProcCommand::new(program)
            .args(args)
            .current_dir(&rpc_workspace)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            Err(anyhow!(
                "query command failed rc={}: {}{}",
                out.status.code().unwrap_or(1),
                stdout,
                stderr
            ))
        } else {
            Ok(stdout.to_string())
        }
    } {
        Ok(raw) => {
            let parsed = parse_tx_query_response(&raw, &requested)?;
            if let Some(got) = normalize_tx_hash(&parsed.tx_hash) {
                if requested != got {
                    bail!(
                        "tx query response hash mismatch: requested={}, got={}",
                        requested,
                        got
                    );
                }
            }
            Ok(parsed)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("TX_NOT_FOUND") {
                if let Some(status) = query_local_tx_status(&requested) {
                    return Ok(TxQueryResponse {
                        tx_hash: requested,
                        status,
                        error: None,
                    });
                }
            }
            Err(e)
        }
    }
}

fn is_terminal_tx_status(status: &str) -> bool {
    matches!(status, "committed" | "fail")
}

fn wait_for_tx<F>(
    tx_hash: &str,
    timeout: Duration,
    interval: Duration,
    mut query_fn: F,
) -> Result<TxQueryResponse>
where
    F: FnMut(&str) -> Result<TxQueryResponse>,
{
    if timeout.is_zero() {
        bail!("tx wait timeout must be greater than 0s");
    }
    if interval.is_zero() {
        bail!("tx wait interval must be greater than 0s");
    }

    let requested = normalize_tx_hash(tx_hash)
        .ok_or_else(|| anyhow!("invalid tx hash for wait (expected hex-like tx hash)"))?;
    let started = Instant::now();
    loop {
        let resp = query_fn(&requested)?;
        if let Some(got) = normalize_tx_hash(&resp.tx_hash) {
            if got != requested {
                bail!(
                    "tx wait response hash mismatch: requested={}, got={}",
                    requested,
                    got
                );
            }
        }
        if is_terminal_tx_status(&resp.status) {
            return Ok(resp);
        }
        if started.elapsed() >= timeout {
            bail!(
                "tx wait timeout after {}s (last_status={})",
                timeout.as_secs(),
                resp.status
            );
        }
        thread::sleep(interval);
    }
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
        .and_then(normalize_tx_status)
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
            "tx": {
                "from": "trnm1pendingplaceholderfrom",
                "to": "trnm1pendingplaceholderto",
                "amount": 0,
                "fee": 0,
                "nonce": 0,
                "signature": "pending"
            },
            "status": "pending",
            "error": null,
            "submitted_at_unix_ms": now_ms,
            "updated_at_unix_ms": now_ms
        }),
    );

    fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

fn emit_pending_tx_hash(tx_hash: &str) -> Result<()> {
    persist_local_pending_tx(tx_hash)?;
    println!("tx_hash={}", tx_hash);
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
                    emit_pending_tx_hash(&tx_hash)?;
                } else {
                    let tx_hash = hash(&[
                        "commit-result",
                        &task_id.to_string(),
                        &worker,
                        &commit_hash,
                        &nonce.to_string(),
                    ]);
                    emit_pending_tx_hash(&tx_hash)?;
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
                    emit_pending_tx_hash(&tx_hash)?;
                } else {
                    let tx_hash = hash(&[
                        "reveal-result",
                        &task_id.to_string(),
                        &result_hash,
                        &salt_hex,
                    ]);
                    emit_pending_tx_hash(&tx_hash)?;
                }
            }
            TxCommand::Query { tx_hash } => {
                let resp = tx_query(&tx_hash)?;
                println!("tx_hash={}", resp.tx_hash);
                println!("status={}", resp.status);
                if let Some(err) = resp.error {
                    println!("error={}", err);
                }
            }
            TxCommand::Wait {
                tx_hash,
                timeout,
                interval,
            } => {
                let resp = wait_for_tx(
                    &tx_hash,
                    Duration::from_secs(timeout),
                    Duration::from_secs(interval),
                    tx_query,
                )?;
                println!("tx_hash={}", resp.tx_hash);
                println!("status={}", resp.status);
                if let Some(err) = resp.error {
                    println!("error={}", err);
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
                    persist_local_pending_tx(&tx_hash)?;
                    let out = TransferTxResponse {
                        tx_hash,
                        status: "pending".into(),
                    };
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    let tx_hash = hash(&["transfer", &req.from, &req.to, &req.amount, &req.denom]);
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
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn wallet_import_hex_check() {
        let ok = ensure_hex_32_bytes(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(ok.len(), 64);
        assert!(ensure_hex_32_bytes("0x1234").is_err());
    }

    #[test]
    fn extract_tx_hash_supports_json_and_kv() {
        assert_eq!(extract_tx_hash("tx_hash=abc123").as_deref(), Some("abc123"));
        assert_eq!(
            extract_tx_hash("{\"tx_hash\":\"deadbeef\",\"status\":\"ok\"}").as_deref(),
            Some("deadbeef")
        );
    }

    #[test]
    fn extract_tx_hash_trims_quotes_and_trailing_punctuation() {
        assert_eq!(
            extract_tx_hash("tx_hash=\"0xabc123\", status=submitted").as_deref(),
            Some("0xabc123")
        );
        assert_eq!(
            extract_tx_hash("{\"txhash\":\"0xdef456;\"}").as_deref(),
            Some("0xdef456")
        );
    }

    #[test]
    fn extract_tx_hash_rejects_non_hex_prefixed_values() {
        assert_eq!(extract_tx_hash("tx_hash=0xzz99").as_deref(), None);
        assert_eq!(
            extract_tx_hash("{\"tx_hash\":\"0xhash-not-hex\"}").as_deref(),
            None
        );
    }

    #[test]
    fn extract_tx_hash_accepts_case_insensitive_keys_and_colon_separator() {
        assert_eq!(
            extract_tx_hash("INFO start TX_HASH:0xbeef01, done").as_deref(),
            Some("0xbeef01")
        );
        assert_eq!(
            extract_tx_hash("meta txHash=0xcafe02;").as_deref(),
            Some("0xcafe02")
        );
        assert_eq!(
            extract_tx_hash("operator transaction_hash:0xface03,").as_deref(),
            Some("0xface03")
        );
        assert_eq!(
            extract_tx_hash("note transactionHash=0xbabe04").as_deref(),
            Some("0xbabe04")
        );
    }

    #[test]
    fn extract_tx_hash_accepts_uppercase_prefixed_hashes_and_json_aliases() {
        assert_eq!(
            extract_tx_hash("tx_hash=0xDEADBEEFCAFEBABE").as_deref(),
            Some("0xdeadbeefcafebabe")
        );
        assert_eq!(
            extract_tx_hash("{\"txHash\":\"ABCDEF012345\",\"status\":\"ok\"}").as_deref(),
            Some("abcdef012345")
        );
    }

    #[test]
    fn tx_query_parse_json_and_kv() {
        let json = "{\"tx_hash\":\"0xabc\",\"status\":\"committed\",\"error\":null}";
        let parsed = parse_tx_query_response(json, "0xabc").unwrap();
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);

        let kv = "tx_hash=0xdef\nstatus=fail\nerror=insufficient balance\n";
        let parsed_kv = parse_tx_query_response(kv, "0xdef").unwrap();
        assert_eq!(parsed_kv.status, "fail");
        assert_eq!(parsed_kv.error.as_deref(), Some("insufficient balance"));
    }

    #[test]
    fn tx_query_parse_json_nested_result_payload() {
        let json = "{\"result\":{\"tx_hash\":\"0xabc\",\"status\":\"success\",\"error\":null}}";
        let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabc");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_accepts_nested_tx_response_wrappers() {
        let wrapped = "{\"tx_response\":{\"txhash\":\"ABC123\",\"code\":0}}";
        let parsed_wrapped = parse_tx_query_response(wrapped, "0xfallback").unwrap();
        assert_eq!(parsed_wrapped.tx_hash, "abc123");
        assert_eq!(parsed_wrapped.status, "committed");
        assert_eq!(parsed_wrapped.error, None);

        let nested = "{\"result\":{\"response\":{\"tx_response\":{\"transactionHash\":\"0xdef456\",\"transactionState\":\"FINALIZED\",\"error\":\"NULL\"}}}}";
        let parsed_nested = parse_tx_query_response(nested, "0xfallback").unwrap();
        assert_eq!(parsed_nested.tx_hash, "0xdef456");
        assert_eq!(parsed_nested.status, "committed");
        assert_eq!(parsed_nested.error, None);
    }

    #[test]
    fn tx_query_parse_json_accepts_camel_and_transaction_hash_keys() {
        let camel = "{\"result\":{\"txHash\":\"0xabc\",\"status\":\"success\"}}";
        let parsed_camel = parse_tx_query_response(camel, "0xfallback").unwrap();
        assert_eq!(parsed_camel.tx_hash, "0xabc");
        assert_eq!(parsed_camel.status, "committed");

        let transaction = "{\"transactionHash\":\"0xdef\",\"status\":\"committed\"}";
        let parsed_transaction = parse_tx_query_response(transaction, "0xfallback").unwrap();
        assert_eq!(parsed_transaction.tx_hash, "0xdef");
        assert_eq!(parsed_transaction.status, "committed");

        let tx_status_snake = "{\"tx_hash\":\"0xaaa\",\"tx_status\":\"accepted\"}";
        let parsed_tx_status_snake =
            parse_tx_query_response(tx_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_snake.tx_hash, "0xaaa");
        assert_eq!(parsed_tx_status_snake.status, "pending");

        let tx_status_camel = "{\"txHash\":\"0xbbb\",\"txStatus\":\"finalized\"}";
        let parsed_tx_status_camel =
            parse_tx_query_response(tx_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_camel.tx_hash, "0xbbb");
        assert_eq!(parsed_tx_status_camel.status, "committed");

        let transaction_status_snake =
            "{\"transactionHash\":\"0xccc\",\"transaction_status\":\"confirmed\"}";
        let parsed_transaction_status_snake =
            parse_tx_query_response(transaction_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_snake.tx_hash, "0xccc");
        assert_eq!(parsed_transaction_status_snake.status, "committed");

        let transaction_status_camel =
            "{\"transaction_hash\":\"0xddd\",\"transactionStatus\":\"timed-out\"}";
        let parsed_transaction_status_camel =
            parse_tx_query_response(transaction_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_camel.tx_hash, "0xddd");
        assert_eq!(parsed_transaction_status_camel.status, "fail");

        let state_alias = "{\"transactionHash\":\"0xeee\",\"transactionState\":\"included\"}";
        let parsed_state_alias = parse_tx_query_response(state_alias, "0xfallback").unwrap();
        assert_eq!(parsed_state_alias.tx_hash, "0xeee");
        assert_eq!(parsed_state_alias.status, "committed");
    }

    #[test]
    fn tx_query_rejects_mismatched_tx_hash() {
        std::env::set_var(
            "TRNM_TX_QUERY_CMD",
            "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
        );
        let got = tx_query("0xbbbb");
        std::env::remove_var("TRNM_TX_QUERY_CMD");
        assert!(got.is_err());
    }

    #[test]
    fn run_template_raw_merges_successful_stdout_and_stderr() {
        let merged = run_template_raw(
            "python3 -c \"import sys; print('tx_hash=0xabc123'); sys.stderr.write('status=committed\\n')\"",
        )
        .unwrap();
        assert!(merged.contains("tx_hash=0xabc123"), "unexpected: {merged}");
        assert!(merged.contains("status=committed"), "unexpected: {merged}");
    }

    #[test]
    fn tx_query_rejects_non_hex_like_tx_hash_before_shell_exec() {
        std::env::set_var(
            "TRNM_TX_QUERY_CMD",
            "printf '{\"tx_hash\":\"0xaaaa\",\"status\":\"committed\"}'",
        );
        let got = tx_query("0xabc; touch /tmp/pwned");
        std::env::remove_var("TRNM_TX_QUERY_CMD");
        assert!(got.is_err());
        let msg = got.err().unwrap().to_string();
        assert!(
            msg.contains("invalid tx hash for query"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn tx_query_parse_kv_is_tolerant_to_case_and_separator() {
        let kv = "TXHASH: 0x777\nSTATUS: committed\nERROR: null\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_kv_treats_nullish_error_variants_as_empty() {
        let kv = "tx_hash=0x777\nstatus=committed\nerror='NULL,'\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);

        let backtick_kv = "tx_hash=0x778\nstatus=`COMMITTED`\nerror=`null`,\n";
        let parsed_backtick = parse_tx_query_response(backtick_kv, "0xfallback").unwrap();
        assert_eq!(parsed_backtick.tx_hash, "0x778");
        assert_eq!(parsed_backtick.status, "committed");
        assert_eq!(parsed_backtick.error, None);
    }

    #[test]
    fn tx_query_parse_kv_unwraps_single_and_backtick_quoted_error_values() {
        let single = "tx_hash=0x781\nstatus=fail\nerror='nonce mismatch'\n";
        let parsed_single = parse_tx_query_response(single, "0xfallback").unwrap();
        assert_eq!(parsed_single.error.as_deref(), Some("nonce mismatch"));

        let backtick = "tx_hash=0x782\nstatus=fail\nerror=`signature invalid`\n";
        let parsed_backtick = parse_tx_query_response(backtick, "0xfallback").unwrap();
        assert_eq!(parsed_backtick.error.as_deref(), Some("signature invalid"));

        let raw_log = "tx_hash=0x783\nstatus=fail\nraw_log='deliver tx failed'\n";
        let parsed_raw_log = parse_tx_query_response(raw_log, "0xfallback").unwrap();
        assert_eq!(parsed_raw_log.error.as_deref(), Some("deliver tx failed"));

        let log_alias = "tx_hash=0x784\nstatus=fail\nlog=`check tx failed`\n";
        let parsed_log_alias = parse_tx_query_response(log_alias, "0xfallback").unwrap();
        assert_eq!(parsed_log_alias.error.as_deref(), Some("check tx failed"));
    }

    #[test]
    fn tx_query_parse_kv_accepts_noisy_single_line_inline_tokens() {
        let noisy = "[adapter] ts=1700000000 status=committed tx_hash=0x8badf00d, error=null";
        let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x8badf00d");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_treats_nullish_error_variants_as_empty() {
        let json = "{\"tx_hash\":\"0x777\",\"status\":\"committed\",\"error\":\"NULL,\"}";
        let parsed = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x777");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_json_preserves_non_string_error_payloads() {
        let json_numeric = "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":404}";
        let parsed_numeric = parse_tx_query_response(json_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_numeric.error.as_deref(), Some("404"));

        let json_obj =
            "{\"tx_hash\":\"0x777\",\"status\":\"fail\",\"error\":{\"code\":\"E_NONCE\"}}";
        let parsed_obj = parse_tx_query_response(json_obj, "0xfallback").unwrap();
        assert_eq!(parsed_obj.error.as_deref(), Some("{\"code\":\"E_NONCE\"}"));

        let json_raw_log =
            "{\"tx_hash\":\"0x778\",\"status\":\"fail\",\"raw_log\":\"deliver tx failed\"}";
        let parsed_raw_log = parse_tx_query_response(json_raw_log, "0xfallback").unwrap();
        assert_eq!(parsed_raw_log.error.as_deref(), Some("deliver tx failed"));

        let json_log = "{\"tx_hash\":\"0x779\",\"status\":\"fail\",\"log\":\"check tx failed\"}";
        let parsed_log = parse_tx_query_response(json_log, "0xfallback").unwrap();
        assert_eq!(parsed_log.error.as_deref(), Some("check tx failed"));
    }

    #[test]
    fn tx_query_parse_json_accepts_scalar_status_aliases() {
        let json_numeric = "{\"tx_hash\":\"0x780\",\"status\":0}";
        let parsed_numeric = parse_tx_query_response(json_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_numeric.tx_hash, "0x780");
        assert_eq!(parsed_numeric.status, "committed");

        let json_nested_numeric = "{\"result\":{\"transactionHash\":\"0x781\",\"transactionState\":12}}";
        let parsed_nested_numeric =
            parse_tx_query_response(json_nested_numeric, "0xfallback").unwrap();
        assert_eq!(parsed_nested_numeric.tx_hash, "0x781");
        assert_eq!(parsed_nested_numeric.status, "fail");
    }

    #[test]
    fn tx_query_parse_infers_status_from_common_code_fields() {
        let json_root_code = "{\"tx_hash\":\"0x701\",\"code\":0}";
        let parsed_root_code = parse_tx_query_response(json_root_code, "0xfallback").unwrap();
        assert_eq!(parsed_root_code.tx_hash, "0x701");
        assert_eq!(parsed_root_code.status, "committed");

        let json_nested_code = "{\"result\":{\"tx_hash\":\"0x702\",\"tx_result\":{\"code\":9}}}";
        let parsed_nested_code = parse_tx_query_response(json_nested_code, "0xfallback").unwrap();
        assert_eq!(parsed_nested_code.tx_hash, "0x702");
        assert_eq!(parsed_nested_code.status, "fail");

        let json_string_code = "{\"tx_hash\":\"0x703\",\"code\":\"0\"}";
        let parsed_string_code = parse_tx_query_response(json_string_code, "0xfallback").unwrap();
        assert_eq!(parsed_string_code.tx_hash, "0x703");
        assert_eq!(parsed_string_code.status, "committed");

        let json_nested_string_code = "{\"result\":{\"tx_hash\":\"0x704\",\"deliver_tx\":{\"code\":\"12\"}}}";
        let parsed_nested_string_code =
            parse_tx_query_response(json_nested_string_code, "0xfallback").unwrap();
        assert_eq!(parsed_nested_string_code.tx_hash, "0x704");
        assert_eq!(parsed_nested_string_code.status, "fail");

        let kv_root_code = "tx_hash=0x705\ncode=0\n";
        let parsed_kv_root_code = parse_tx_query_response(kv_root_code, "0xfallback").unwrap();
        assert_eq!(parsed_kv_root_code.tx_hash, "0x705");
        assert_eq!(parsed_kv_root_code.status, "committed");

        let kv_deliver_code = "tx_hash=0x706\ndeliver_tx_code=12\n";
        let parsed_kv_deliver_code =
            parse_tx_query_response(kv_deliver_code, "0xfallback").unwrap();
        assert_eq!(parsed_kv_deliver_code.tx_hash, "0x706");
        assert_eq!(parsed_kv_deliver_code.status, "fail");
    }

    #[test]
    fn tx_query_parse_normalizes_status_aliases_and_punctuation() {
        let kv = "txhash=0xabc\nstatus=FAILED,\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabc");
        assert_eq!(parsed.status, "fail");

        let json = "{\"tx_hash\":\"0xdef\",\"status\":\"ok\"}";
        let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed_json.status, "committed");

        let noisy_punct = "tx_hash=0xeee\nstatus=success!?\n";
        let parsed_noisy = parse_tx_query_response(noisy_punct, "0xfallback").unwrap();
        assert_eq!(parsed_noisy.status, "committed");

        let succeeded_alias = "tx_hash=0xeee1\nstatus=succeeded\n";
        let parsed_succeeded = parse_tx_query_response(succeeded_alias, "0xfallback").unwrap();
        assert_eq!(parsed_succeeded.status, "committed");

        let confirmed_alias = "tx_hash=0xeee2\nstatus=confirmed\n";
        let parsed_confirmed = parse_tx_query_response(confirmed_alias, "0xfallback").unwrap();
        assert_eq!(parsed_confirmed.status, "committed");

        let single_quoted = "tx_hash=0xeff\nstatus='committed'\n";
        let parsed_single_quoted = parse_tx_query_response(single_quoted, "0xfallback").unwrap();
        assert_eq!(parsed_single_quoted.status, "committed");

        let wrapped_status = "tx_hash=0xeff1\nstatus=(`confirmed`,)\n";
        let parsed_wrapped_status = parse_tx_query_response(wrapped_status, "0xfallback").unwrap();
        assert_eq!(parsed_wrapped_status.status, "committed");

        let rejected_alias = "tx_hash=0xef0\nstatus=REJECTED\n";
        let parsed_rejected = parse_tx_query_response(rejected_alias, "0xfallback").unwrap();
        assert_eq!(parsed_rejected.status, "fail");

        let timed_out_alias = "tx_hash=0xef1\nstatus=timed_out\n";
        let parsed_timed_out = parse_tx_query_response(timed_out_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out.status, "fail");

        let timed_out_hyphen_alias = "tx_hash=0xef2\nstatus=timed-out\n";
        let parsed_timed_out_hyphen =
            parse_tx_query_response(timed_out_hyphen_alias, "0xfallback").unwrap();
        assert_eq!(parsed_timed_out_hyphen.status, "fail");

        let submitted_alias = "tx_hash=0xef3\nstatus=submitted\n";
        let parsed_submitted = parse_tx_query_response(submitted_alias, "0xfallback").unwrap();
        assert_eq!(parsed_submitted.status, "pending");

        let accepted_alias = "tx_hash=0xef4\nstatus=accepted\n";
        let parsed_accepted = parse_tx_query_response(accepted_alias, "0xfallback").unwrap();
        assert_eq!(parsed_accepted.status, "pending");

        let processing_alias = "tx_hash=0xef41\nstatus=processing\n";
        let parsed_processing = parse_tx_query_response(processing_alias, "0xfallback").unwrap();
        assert_eq!(parsed_processing.status, "pending");

        let in_progress_alias = "tx_hash=0xef42\nstatus=in_progress\n";
        let parsed_in_progress = parse_tx_query_response(in_progress_alias, "0xfallback").unwrap();
        assert_eq!(parsed_in_progress.status, "pending");

        let in_flight_alias = "tx_hash=0xef43\nstatus=in-flight\n";
        let parsed_in_flight = parse_tx_query_response(in_flight_alias, "0xfallback").unwrap();
        assert_eq!(parsed_in_flight.status, "pending");

        let included_alias = "tx_hash=0xef5\nstatus=included\n";
        let parsed_included = parse_tx_query_response(included_alias, "0xfallback").unwrap();
        assert_eq!(parsed_included.status, "committed");

        let finalized_alias = "tx_hash=0xef6\nstatus=finalized\n";
        let parsed_finalized = parse_tx_query_response(finalized_alias, "0xfallback").unwrap();
        assert_eq!(parsed_finalized.status, "committed");

        let expired_alias = "tx_hash=0xef7\nstatus=expired\n";
        let parsed_expired = parse_tx_query_response(expired_alias, "0xfallback").unwrap();
        assert_eq!(parsed_expired.status, "fail");
    }

    #[test]
    fn tx_query_parse_kv_ignores_noisy_lines_and_uses_valid_status() {
        let noisy = "[rpc] connecting...\nrandom line without kv\ntx_hash=0x999\nINFO: still processing\nstatus=committed\n";
        let parsed = parse_tx_query_response(noisy, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0x999");
        assert_eq!(parsed.status, "committed");
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn tx_query_parse_normalizes_quoted_or_punctuated_tx_hash() {
        let kv = "tx_hash='0xABCD1234',\nstatus=committed\n";
        let parsed = parse_tx_query_response(kv, "0xfallback").unwrap();
        assert_eq!(parsed.tx_hash, "0xabcd1234");

        let json = "{\"tx_hash\":\"0xDEADbeef,\",\"status\":\"committed\"}";
        let parsed_json = parse_tx_query_response(json, "0xfallback").unwrap();
        assert_eq!(parsed_json.tx_hash, "0xdeadbeef");

        let nested_wrappers = "tx_hash=(`\"0xBEEF42\"`,)\nstatus=committed\n";
        let parsed_nested = parse_tx_query_response(nested_wrappers, "0xfallback").unwrap();
        assert_eq!(parsed_nested.tx_hash, "0xbeef42");
    }

    #[test]
    fn tx_query_parse_kv_accepts_transaction_hash_aliases() {
        let snake = "transaction_hash=0xabc123\nstatus=committed\n";
        let parsed_snake = parse_tx_query_response(snake, "0xfallback").unwrap();
        assert_eq!(parsed_snake.tx_hash, "0xabc123");

        let compact = "transactionHash=0xdef456\nstatus=committed\n";
        let parsed_compact = parse_tx_query_response(compact, "0xfallback").unwrap();
        assert_eq!(parsed_compact.tx_hash, "0xdef456");

        let tx_status_snake = "tx_hash=0xaaa111\ntx_status=queued\n";
        let parsed_tx_status_snake =
            parse_tx_query_response(tx_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_snake.tx_hash, "0xaaa111");
        assert_eq!(parsed_tx_status_snake.status, "pending");

        let tx_status_compact = "txhash=0xbbb222\ntxStatus=timed-out\n";
        let parsed_tx_status_compact =
            parse_tx_query_response(tx_status_compact, "0xfallback").unwrap();
        assert_eq!(parsed_tx_status_compact.tx_hash, "0xbbb222");
        assert_eq!(parsed_tx_status_compact.status, "fail");

        let transaction_status_snake = "transaction_hash=0xccc333\ntransaction_status=confirmed\n";
        let parsed_transaction_status_snake =
            parse_tx_query_response(transaction_status_snake, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_snake.tx_hash, "0xccc333");
        assert_eq!(parsed_transaction_status_snake.status, "committed");

        let transaction_status_camel = "transactionHash=0xddd444\ntransactionStatus=rejected\n";
        let parsed_transaction_status_camel =
            parse_tx_query_response(transaction_status_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_status_camel.tx_hash, "0xddd444");
        assert_eq!(parsed_transaction_status_camel.status, "fail");

        let transaction_state_camel = "transactionHash=0xeee555\ntransactionState=finalized\n";
        let parsed_transaction_state_camel =
            parse_tx_query_response(transaction_state_camel, "0xfallback").unwrap();
        assert_eq!(parsed_transaction_state_camel.tx_hash, "0xeee555");
        assert_eq!(parsed_transaction_state_camel.status, "committed");
    }

    #[test]
    fn tx_query_parse_rejects_invalid_tx_hash_if_field_is_present() {
        let bad_json = "{\"tx_hash\":\"not-a-hash\",\"status\":\"committed\"}";
        let err_json = parse_tx_query_response(bad_json, "0xabc").unwrap_err();
        assert!(
            err_json
                .to_string()
                .contains("invalid tx_hash field in tx query response"),
            "unexpected: {err_json}"
        );

        let bad_kv = "tx_hash=not-a-hash\nstatus=committed\n";
        let err_kv = parse_tx_query_response(bad_kv, "0xabc").unwrap_err();
        assert!(
            err_kv
                .to_string()
                .contains("invalid tx_hash field in tx query response"),
            "unexpected: {err_kv}"
        );
    }

    #[test]
    fn wait_for_tx_rejects_zero_timeout() {
        let result = wait_for_tx(
            "0xabc123",
            Duration::from_secs(0),
            Duration::from_secs(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xabc123".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("tx wait timeout must be greater than 0s"));
    }

    #[test]
    fn wait_for_tx_rejects_zero_interval() {
        let result = wait_for_tx(
            "0xabc123",
            Duration::from_secs(1),
            Duration::from_secs(0),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xabc123".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("tx wait interval must be greater than 0s"));
    }

    #[test]
    fn wait_for_tx_timeout() {
        let result = wait_for_tx(
            "0xaaa",
            Duration::from_millis(1),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xaaa".to_string(),
                    status: "pending".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait timeout"),
            "expected timeout error, got: {msg}"
        );
    }

    #[test]
    fn wait_for_tx_success() {
        let result = wait_for_tx(
            "0xbbb",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xbbb".to_string(),
                    status: "committed".to_string(),
                    error: None,
                })
            },
        )
        .unwrap();
        assert_eq!(result.status, "committed");
    }

    #[test]
    fn wait_for_tx_rejects_hash_mismatch() {
        let result = wait_for_tx(
            "0xbbb",
            Duration::from_millis(10),
            Duration::from_millis(1),
            |_| {
                Ok(TxQueryResponse {
                    tx_hash: "0xccc".to_string(),
                    status: "committed".to_string(),
                    error: None,
                })
            },
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("tx wait response hash mismatch"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn tpl_replacement_works() {
        let got = tpl("send {from} {to} {amount}".to_string(), "from", "alice");
        let got = tpl(got, "to", "bob");
        let got = tpl(got, "amount", "7");
        assert_eq!(got, "send alice bob 7");
    }

    #[test]
    fn persist_local_pending_tx_keeps_pending_state() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tx_hash = format!("0x{:064x}", nonce);
        persist_local_pending_tx(&tx_hash).unwrap();

        let status = query_local_tx_status(&tx_hash).unwrap();
        assert_eq!(status, "pending");

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn query_local_tx_status_normalizes_aliases_and_rejects_unknown() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let ok_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let completed_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let inflight_hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let unknown_hash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let payload = format!(
            "{{\n  \"{}\": {{\"status\": \"success!\"}},\n  \"{}\": {{\"status\": \"done\"}},\n  \"{}\": {{\"status\": \"in_progress\"}},\n  \"{}\": {{\"status\": \"mystery\"}}\n}}",
            ok_hash, completed_hash, inflight_hash, unknown_hash
        );
        std::fs::write(&path, payload).unwrap();

        assert_eq!(query_local_tx_status(ok_hash).as_deref(), Some("committed"));
        assert_eq!(query_local_tx_status(completed_hash).as_deref(), Some("committed"));
        assert_eq!(query_local_tx_status(inflight_hash).as_deref(), Some("pending"));
        assert_eq!(query_local_tx_status(unknown_hash), None);

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn persist_local_pending_tx_overwrites_existing_terminal_state_with_pending() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let tx_hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let payload = format!(
            "{{\n  \"{}\": {{\"status\": \"committed\", \"updated_at_unix_ms\": 1}}\n}}",
            tx_hash
        );
        std::fs::write(&path, payload).unwrap();

        persist_local_pending_tx(tx_hash).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            parsed[tx_hash]["status"].as_str(),
            Some("pending"),
            "persist_local_pending_tx should reset tracked txs to pending on fresh submit"
        );
        assert_eq!(query_local_tx_status(tx_hash).as_deref(), Some("pending"));

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }

    #[test]
    fn emit_pending_tx_hash_tracks_reveal_like_submissions() {
        let _guard = ENV_LOCK.lock().unwrap();
        let unique = format!(
            "trnm-cli-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::env::set_var("TRNM_RPC_TX_FILE", &path);

        let tx_hash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        emit_pending_tx_hash(tx_hash).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed[tx_hash]["tx_hash"].as_str(), Some(tx_hash));
        assert_eq!(query_local_tx_status(tx_hash).as_deref(), Some("pending"));

        let _ = std::fs::remove_file(&path);
        std::env::remove_var("TRNM_RPC_TX_FILE");
    }
}
