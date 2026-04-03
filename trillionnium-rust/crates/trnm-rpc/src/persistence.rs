use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use trnm_rpc::{AccountState, InMemoryTransferLedger, TxLifecycleRecord};

use crate::fsutil::atomic_write_text_file;

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct FaucetRateEntry {
    pub(crate) window_start_unix_ms: u128,
    pub(crate) count_in_window: u32,
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
