use super::*;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, MutexGuard, OnceLock,
};

pub(crate) fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) fn lock_env<'a>() -> MutexGuard<'a, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

pub(crate) fn unique_tmp_path(prefix: &str, ext: &str) -> PathBuf {
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

pub(crate) fn with_market_score_env(vars: &[(&str, &str)], f: impl FnOnce()) {
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

pub(crate) fn with_market_path_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
    let _guard = lock_env();
    let keys = [
        "TRNM_RPC_MARKET_TASKS_FILE",
        "TRNM_RPC_MARKET_BIDS_FILE",
        "TRNM_RPC_INGRESS_FILE",
        MARKET_REPUTATION_FILE_ENV,
        TASK_STATE_FILE_ENV,
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

pub(crate) fn faucet_env_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

pub(crate) fn clear_faucet_env() {
    std::env::remove_var("TRNM_RPC_FAUCET_WINDOW_SECONDS");
    std::env::remove_var("TRNM_RPC_FAUCET_MAX_REQUESTS");
}
