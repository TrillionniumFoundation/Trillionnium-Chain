pub(crate) const DEFAULT_TX_ADAPTER_MAX_RETRIES: u32 = 3;
pub(crate) const DEFAULT_TX_ADAPTER_BACKOFF_MS: u64 = 200;
pub(crate) const DEFAULT_LLM_ADAPTER_MAX_RETRIES: u32 = 2;
pub(crate) const DEFAULT_LLM_ADAPTER_BACKOFF_MS: u64 = 200;
pub(crate) const DEFAULT_LLM_ADAPTER_TIMEOUT_MS: u64 = 10_000;

pub(crate) const TX_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_TX_ADAPTER_MAX_RETRIES";
pub(crate) const TX_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_TX_ADAPTER_BACKOFF_MS";
pub(crate) const LLM_ADAPTER_MAX_RETRIES_ENV: &str = "TRNM_LLM_ADAPTER_MAX_RETRIES";
pub(crate) const LLM_ADAPTER_BACKOFF_MS_ENV: &str = "TRNM_LLM_ADAPTER_BACKOFF_MS";
pub(crate) const LLM_ADAPTER_TIMEOUT_ENV: &str = "TRNM_LLM_ADAPTER_TIMEOUT_MS";
pub(crate) const PROOF_ADAPTER_ENV: &str = "TRNM_PROOF_ADAPTER";
pub(crate) const WORKER_EVENT_LOG_ENV: &str = "TRNM_WORKER_EVENT_LOG";
pub(crate) const WORKER_PROGRESS_LOG_ENV: &str = "TRNM_WORKER_PROGRESS_LOG";

pub(crate) const RC_OK: i32 = 0;
pub(crate) const RC_DUPLICATE: i32 = 9;
pub(crate) const RC_NONCE_REJECTED: i32 = 10;
pub(crate) const RC_SLO_VIOLATION: i32 = 11;
pub(crate) const RC_SKIPPED: i32 = -1;
