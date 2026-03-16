use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, MutexGuard, OnceLock,
};
use trnm_types::CapabilityScope;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_env<'a>() -> MutexGuard<'a, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn unique_tmp_path(prefix: &str, ext: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{}-{}-{}-{}.{}",
        prefix,
        std::process::id(),
        now_ms(),
        seq,
        ext
    ))
}

fn write_json_fixture<T: Serialize>(prefix: &str, value: &T) -> PathBuf {
    let path = unique_tmp_path(prefix, "json");
    let raw = serde_json::to_string_pretty(value).expect("serialize fixture");
    fs::write(&path, raw).expect("write fixture");
    path
}

fn oracle_policy_fixture() -> OraclePolicy {
    OraclePolicy {
        min_sources: 2,
        max_staleness_ms: 5_000,
        max_deviation_bps: 500,
        max_update_rate_per_window: 60,
    }
}

fn oracle_snapshot_fixture(
    value: i128,
    median: Option<i128>,
    snapshot_ts_ms: u64,
) -> OracleSnapshot {
    OracleSnapshot::new(
        "btc/usd",
        value,
        vec![
            trnm_oracle::OracleSourceId::parse("coingecko").expect("source"),
            trnm_oracle::OracleSourceId::parse("chainlink").expect("source"),
        ],
        2,
        median,
        Some(120),
        1_000,
        2_000,
        snapshot_ts_ms,
    )
    .expect("snapshot fixture")
}

fn with_market_score_env(vars: &[(&str, &str)], f: impl FnOnce()) {
    let _guard = lock_env();
    let keys = [
        MARKET_PRICE_WEIGHT_ENV,
        MARKET_REPUTATION_WEIGHT_ENV,
        MARKET_REPUTATION_CLAMP_ENV,
    ];
    let prev: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
        .collect();

    for (k, v) in vars {
        unsafe { std::env::set_var(k, v) };
    }

    let run = catch_unwind(AssertUnwindSafe(f));

    for (k, v) in prev {
        match v {
            Some(val) => unsafe { std::env::set_var(&k, val) },
            None => unsafe { std::env::remove_var(&k) },
        }
    }

    if let Err(panic) = run {
        std::panic::resume_unwind(panic);
    }
}

fn with_market_path_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
    let _guard = lock_env();
    let keys = [
        "TRNM_RPC_MARKET_TASKS_FILE",
        "TRNM_RPC_MARKET_BIDS_FILE",
        "TRNM_RPC_INGRESS_FILE",
        MARKET_REPUTATION_FILE_ENV,
    ];
    let prev: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
        .collect();

    for (k, v) in vars {
        match v {
            Some(val) => unsafe { std::env::set_var(k, val) },
            None => unsafe { std::env::remove_var(k) },
        }
    }

    let run = catch_unwind(AssertUnwindSafe(f));

    for (k, v) in prev {
        match v {
            Some(val) => unsafe { std::env::set_var(&k, val) },
            None => unsafe { std::env::remove_var(&k) },
        }
    }

    if let Err(panic) = run {
        std::panic::resume_unwind(panic);
    }
}

#[cfg(test)]
#[path = "tests_rpc_oracle_market.rs"]
mod tests_rpc_oracle_market;

#[cfg(test)]
#[path = "tests_rpc_governance.rs"]
mod tests_rpc_governance;

#[cfg(test)]
#[path = "tests_rpc_challenge.rs"]
mod tests_rpc_challenge;

#[cfg(test)]
#[path = "tests_rpc_misc.rs"]
mod tests_rpc_misc;
