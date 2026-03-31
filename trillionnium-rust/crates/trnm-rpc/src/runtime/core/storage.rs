use super::*;

pub(crate) fn atomic_write_text_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}-{}",
        file_name,
        std::process::id(),
        now_ms()
    ));

    {
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    fs::rename(&tmp, path)?;

    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
    }

    Ok(())
}

pub(crate) fn account_state_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_ACCOUNTS_FILE") {
        return path;
    }
    run_root().join("run/rpc/accounts.json")
}

pub(crate) fn load_account_state(path: &Path) -> BTreeMap<String, AccountState> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<BTreeMap<String, AccountState>>(&raw) {
        Ok(accounts) => accounts,
        Err(err) => {
            eprintln!(
                "[trnm-rpc][warn][ACCOUNT_STATE_PARSE] path={} err={}",
                path.display(),
                err
            );
            BTreeMap::new()
        }
    }
}

pub(crate) fn save_account_state(
    path: &Path,
    accounts: &BTreeMap<String, AccountState>,
) -> Result<()> {
    let content = serde_json::to_string_pretty(accounts)?;
    atomic_write_text_file(path, &content)
}

pub(crate) fn tx_lifecycle_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_TX_FILE") {
        return path;
    }
    run_root().join("run/rpc/txs.json")
}

pub(crate) fn faucet_limits_file() -> PathBuf {
    if let Some(path) = normalized_path_from_env("TRNM_RPC_FAUCET_LIMITS_FILE") {
        return path;
    }
    run_root().join("run/rpc/faucet_limits.json")
}

pub(crate) fn load_faucet_limits(path: &Path) -> BTreeMap<String, FaucetRateEntry> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<BTreeMap<String, FaucetRateEntry>>(&raw) {
        Ok(limits) => limits,
        Err(err) => {
            eprintln!(
                "[trnm-rpc][warn][FAUCET_LIMITS_PARSE] path={} err={}",
                path.display(),
                err
            );
            BTreeMap::new()
        }
    }
}

pub(crate) fn save_faucet_limits(
    path: &Path,
    limits: &BTreeMap<String, FaucetRateEntry>,
) -> Result<()> {
    let content = serde_json::to_string_pretty(limits)?;
    atomic_write_text_file(path, &content)
}

pub(crate) fn load_tx_lifecycle(path: &Path) -> BTreeMap<String, TxLifecycleRecord> {
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<BTreeMap<String, TxLifecycleRecord>>(&raw) {
        Ok(txs) => txs,
        Err(err) => {
            eprintln!(
                "[trnm-rpc][warn][TX_LIFECYCLE_PARSE] path={} err={}",
                path.display(),
                err
            );
            BTreeMap::new()
        }
    }
}

pub(crate) fn save_tx_lifecycle(
    path: &Path,
    txs: &BTreeMap<String, TxLifecycleRecord>,
) -> Result<()> {
    let content = serde_json::to_string_pretty(txs)?;
    atomic_write_text_file(path, &content)
}

pub(crate) fn accounts_to_ledger(
    accounts: &BTreeMap<String, AccountState>,
) -> InMemoryTransferLedger {
    let mut ledger = InMemoryTransferLedger::new();
    for account in accounts.values() {
        ledger.set_account(account.address.clone(), account.balance, account.nonce);
    }
    ledger
}

pub(crate) fn ledger_to_accounts(
    ledger: &InMemoryTransferLedger,
    accounts: &mut BTreeMap<String, AccountState>,
) {
    for account in accounts.values_mut() {
        account.balance = ledger.balance_of(&account.address);
        account.nonce = ledger.next_nonce_of(&account.address);
    }
}

pub(crate) fn rpc_fail(err: RpcErrorResponse) -> anyhow::Error {
    let body = serde_json::to_string_pretty(&err).unwrap_or_else(|_| {
        format!(
            "{{\"code\":\"{}\",\"message\":\"{}\"}}",
            err.code, err.message
        )
    });
    anyhow::anyhow!(body)
}

pub(crate) fn clamp_limit(
    op: &str,
    requested: usize,
    default_limit: usize,
    max_limit: usize,
) -> usize {
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

pub(crate) fn push_tail_limited<T>(items: &mut Vec<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    items.push(item);
    if items.len() > limit {
        let keep_from = items.len() - limit;
        items.drain(0..keep_from);
    }
}

pub(crate) fn normalize_tx_hash_lookup(raw: &str) -> String {
    let mut normalized = raw.trim_matches(|c: char| {
        c.is_ascii_whitespace() || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
    });

    loop {
        let is_wrapped = normalized.len() >= 2
            && ["\"", "'", "`"]
                .iter()
                .any(|q| normalized.starts_with(q) && normalized.ends_with(q));

        if is_wrapped {
            normalized = normalized[1..normalized.len() - 1].trim_matches(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
            });
            continue;
        }
        break;
    }

    let normalized = normalized.to_ascii_lowercase();
    for delimiter in ['=', ':'] {
        if let Some((k, v)) = normalized.split_once(delimiter) {
            let key = k.trim();
            let normalized_key: String =
                key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if normalized_key == "txhash" || normalized_key == "hash" {
                let mut value = v.trim_matches(|c: char| {
                    c.is_ascii_whitespace()
                        || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
                });
                while let Some(stripped) = value.strip_prefix('=') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                while let Some(stripped) = value.strip_prefix(':') {
                    value = stripped.trim_start_matches(|c: char| c.is_ascii_whitespace());
                }
                loop {
                    let is_wrapped = value.len() >= 2
                        && ["\"", "'", "`"]
                            .iter()
                            .any(|q| value.starts_with(q) && value.ends_with(q));
                    if is_wrapped {
                        value = value[1..value.len() - 1].trim_matches(|c: char| {
                            c.is_ascii_whitespace()
                                || matches!(c, ',' | ';' | '.' | '(' | ')' | '[' | ']' | '{' | '}')
                        });
                        continue;
                    }
                    break;
                }
                return value.to_string();
            }
        }
    }

    normalized
}

pub(crate) fn is_hex_like_tx_hash(raw: &str) -> bool {
    raw.strip_prefix("0x")
        .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

pub(crate) fn resolve_ops_window(
    window: Option<OpsWindowArg>,
    from_unix_ms: Option<u128>,
    to_unix_ms: Option<u128>,
    now_unix_ms: u128,
) -> Result<Option<(u128, u128, String)>> {
    match window {
        None => Ok(None),
        Some(OpsWindowArg::H24) => Ok(Some((
            now_unix_ms.saturating_sub(24 * 60 * 60 * 1000),
            now_unix_ms,
            "24h".to_string(),
        ))),
        Some(OpsWindowArg::D7) => Ok(Some((
            now_unix_ms.saturating_sub(7 * 24 * 60 * 60 * 1000),
            now_unix_ms,
            "7d".to_string(),
        ))),
        Some(OpsWindowArg::Custom) => {
            let from = from_unix_ms
                .ok_or_else(|| anyhow!("--from-unix-ms is required when --window custom"))?;
            let to = to_unix_ms
                .ok_or_else(|| anyhow!("--to-unix-ms is required when --window custom"))?;
            if from > to {
                bail!("invalid custom window: from_unix_ms ({from}) must be <= to_unix_ms ({to})");
            }
            let span = to.saturating_sub(from);
            if span > OPS_WINDOW_CUSTOM_MAX_MS {
                bail!(
                    "custom window too large: span_ms ({span}) exceeds max_ms ({OPS_WINDOW_CUSTOM_MAX_MS})"
                );
            }
            Ok(Some((from, to, "custom".to_string())))
        }
    }
}
