use crate::envpaths::{
    account_state_file, env_u32_with_min, env_u64_with_min, faucet_limits_file, tx_lifecycle_file,
};
use crate::market_io::acquire_market_file_lock;
use crate::persistence::{
    accounts_to_ledger, ledger_to_accounts, load_account_state, load_faucet_limits,
    load_tx_lifecycle, save_account_state, save_faucet_limits, save_tx_lifecycle,
};
use crate::rpc_util::rpc_fail;
use crate::{is_hex_like_tx_hash, normalize_tx_hash_lookup};
use anyhow::Result;
use trnm_rpc::{
    get_tx, query_account_state, submit_tx, validate_trnm_address, AccountBalanceQueryResponse,
    AccountNonceQueryResponse, AccountState, FaucetRequestResponse, GetTxError, RpcErrorResponse,
};
use trnm_types::TransferTx;

pub(crate) const FAUCET_WINDOW_SECONDS_DEFAULT: u64 = 60;
pub(crate) const FAUCET_WINDOW_SECONDS_MIN: u64 = 1;
pub(crate) const FAUCET_MAX_REQUESTS_DEFAULT: u32 = 1;
pub(crate) const FAUCET_MAX_REQUESTS_MIN: u32 = 1;

fn faucet_window_ms(window_seconds: u64) -> u128 {
    (window_seconds as u128) * 1000
}

fn faucet_window_rolled_over(
    window_start_unix_ms: u128,
    now_unix_ms: u128,
    window_ms: u128,
) -> bool {
    window_start_unix_ms == 0 || now_unix_ms.saturating_sub(window_start_unix_ms) >= window_ms
}

fn faucet_next_allowed_unix_ms(window_start_unix_ms: u128, window_ms: u128) -> u128 {
    window_start_unix_ms.saturating_add(window_ms)
}

pub(crate) fn handle_query_balance(address: &str) -> Result<()> {
    let accounts = load_account_state(&account_state_file());
    let account = query_account_state(&accounts, address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
    let out = AccountBalanceQueryResponse {
        address: account.address,
        balance: account.balance,
        version: 1,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_query_nonce(address: &str) -> Result<()> {
    let accounts = load_account_state(&account_state_file());
    let account = query_account_state(&accounts, address).map_err(|e| rpc_fail(e.to_rpc_error()))?;
    let out = AccountNonceQueryResponse {
        address: account.address,
        nonce: account.nonce,
        version: 1,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_send_tx(
    from: String,
    to: String,
    amount: u128,
    fee: u128,
    nonce: u64,
    signature: String,
    now_unix_ms: u128,
) -> Result<()> {
    let tx_path = tx_lifecycle_file();
    let _tx_lock = acquire_market_file_lock(&tx_path)?;
    let mut txs = load_tx_lifecycle(&tx_path);
    let tx = TransferTx {
        from,
        to,
        amount,
        fee,
        nonce,
        signature,
    };
    let out = submit_tx(&mut txs, tx, now_unix_ms);
    save_tx_lifecycle(&tx_path, &txs)?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_get_tx(tx_hash: &str, now_unix_ms: u128) -> Result<()> {
    let tx_path = tx_lifecycle_file();
    let _tx_lock = acquire_market_file_lock(&tx_path)?;
    let mut txs = load_tx_lifecycle(&tx_path);

    let account_path = account_state_file();
    let _account_lock = acquire_market_file_lock(&account_path)?;
    let mut accounts = load_account_state(&account_path);
    let mut ledger = accounts_to_ledger(&accounts);
    let tx_hash = normalize_tx_hash_lookup(tx_hash);
    if !is_hex_like_tx_hash(&tx_hash) {
        return Err(rpc_fail(RpcErrorResponse {
            code: "INVALID_ARGUMENT",
            message: format!(
                "invalid tx hash format: expected 0x-prefixed hexadecimal, got {}",
                tx_hash
            ),
        }));
    }

    let out = get_tx(&mut txs, &mut ledger, &tx_hash, now_unix_ms).map_err(|e| match e {
        GetTxError::NotFound(tx_hash) => rpc_fail(RpcErrorResponse {
            code: "TX_NOT_FOUND",
            message: format!("tx not found: {}", tx_hash),
        }),
    })?;

    if matches!(out.status, trnm_rpc::TxStatus::Committed) {
        if let Some(rec) = txs.get(&tx_hash) {
            for address in [&rec.tx.from, &rec.tx.to] {
                accounts.entry(address.clone()).or_insert(AccountState {
                    address: address.clone(),
                    balance: ledger.balance_of(address),
                    nonce: ledger.next_nonce_of(address),
                });
            }
        }
    }

    ledger_to_accounts(&ledger, &mut accounts);
    save_tx_lifecycle(&tx_path, &txs)?;
    save_account_state(&account_path, &accounts)?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_faucet_request(address: String, amount: u128, now_unix_ms: u128) -> Result<()> {
    let window_seconds = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests_in_window = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    if validate_trnm_address(&address).is_err() {
        let out = FaucetRequestResponse {
            ok: false,
            code: "INVALID_ADDRESS".into(),
            message: format!("invalid address format: {}", address),
            address,
            requested_amount: amount,
            granted_amount: 0,
            balance: None,
            nonce: None,
            window_seconds,
            next_allowed_unix_ms: now_unix_ms,
            version: 1,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let limits_path = faucet_limits_file();
    let _limits_lock = acquire_market_file_lock(&limits_path)?;
    let mut limits = load_faucet_limits(&limits_path);
    let window_ms = faucet_window_ms(window_seconds);
    let next_allowed_unix_ms;
    let mut allowed = true;

    {
        let entry = limits.entry(address.clone()).or_default();
        if faucet_window_rolled_over(entry.window_start_unix_ms, now_unix_ms, window_ms) {
            entry.window_start_unix_ms = now_unix_ms;
            entry.count_in_window = 0;
        }
        if entry.count_in_window >= max_requests_in_window {
            allowed = false;
        }
        next_allowed_unix_ms = faucet_next_allowed_unix_ms(entry.window_start_unix_ms, window_ms);
    }

    let account_path = account_state_file();
    let _account_lock = acquire_market_file_lock(&account_path)?;
    let mut accounts = load_account_state(&account_path);

    if !allowed {
        let acct = accounts.get(&address).cloned();
        let out = FaucetRequestResponse {
            ok: false,
            code: "RATE_LIMITED".into(),
            message: "faucet rate limit exceeded".into(),
            address,
            requested_amount: amount,
            granted_amount: 0,
            balance: acct.as_ref().map(|a| a.balance),
            nonce: acct.as_ref().map(|a| a.nonce),
            window_seconds,
            next_allowed_unix_ms,
            version: 1,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let (new_balance, nonce) = {
        let acct = accounts.entry(address.clone()).or_insert(AccountState {
            address: address.clone(),
            balance: 0,
            nonce: 0,
        });
        acct.balance = acct.balance.saturating_add(amount);
        (acct.balance, acct.nonce)
    };

    if let Some(entry) = limits.get_mut(&address) {
        entry.count_in_window = entry.count_in_window.saturating_add(1);
    }

    save_account_state(&account_path, &accounts)?;
    save_faucet_limits(&limits_path, &limits)?;

    let out = FaucetRequestResponse {
        ok: true,
        code: "OK".into(),
        message: "faucet granted".into(),
        address,
        requested_amount: amount,
        granted_amount: amount,
        balance: Some(new_balance),
        nonce: Some(nonce),
        window_seconds,
        next_allowed_unix_ms,
        version: 1,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
