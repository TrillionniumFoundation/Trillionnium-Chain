#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_attempts: u32,
    pub circuit_breaker_threshold: u32,
    pub circuit_open_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 200,
            max_backoff_ms: 10_000,
            max_attempts: 8,
            circuit_breaker_threshold: 5,
            circuit_open_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open { until_unix_ms: u128 },
}

#[derive(Debug, Clone)]
pub struct RetentionConfig {
    pub dedup_ttl_ms: u64,
    pub pending_ttl_ms: u64,
    pub cleanup_interval_ms: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            dedup_ttl_ms: 10 * 60 * 1_000,
            pending_ttl_ms: 24 * 60 * 60 * 1_000,
            cleanup_interval_ms: 1_000,
        }
    }
}

pub struct ReliabilityEngine<S: ReliabilityStore> {
    store: S,
    retry: RetryConfig,
    retention: RetentionConfig,
    last_cleanup_at_unix_ms: Option<u128>,
    circuit_state: CircuitState,
    consecutive_retry_exhausted: u32,
    retry_exhausted_total: AtomicU64,
    circuit_open_total: AtomicU64,
    circuit_recovered_total: AtomicU64,
    collect_rr_cursor: usize,
}

fn sanitize_retry_config(mut retry: RetryConfig) -> RetryConfig {
    if retry.base_backoff_ms == 0 {
        retry.base_backoff_ms = 1;
    }
    if retry.max_backoff_ms == 0 {
        retry.max_backoff_ms = retry.base_backoff_ms;
    }
    if retry.max_backoff_ms < retry.base_backoff_ms {
        retry.max_backoff_ms = retry.base_backoff_ms;
    }
    // Prevent zeroed limits from causing immediate drop/open loops under
    // misconfigured environments.
    if retry.max_attempts == 0 {
        retry.max_attempts = 1;
    }
    if retry.circuit_breaker_threshold == 0 {
        retry.circuit_breaker_threshold = 1;
    }
    if retry.circuit_open_ms == 0 {
        retry.circuit_open_ms = retry.base_backoff_ms;
    }
    if retry.circuit_open_ms < retry.base_backoff_ms {
        // Keep circuit-open window at least one base retry interval so repeated
        // retry-exhaustion rounds cannot immediately re-open under undersized
        // operator configs.
        retry.circuit_open_ms = retry.base_backoff_ms;
    }
    retry
}

fn sanitize_retention_config(mut retention: RetentionConfig) -> RetentionConfig {
    // Zero dedup ttl disables idempotency memory and allows immediate duplicate
    // replays under concurrent ingress. Keep a 1ms floor so dedup remains active.
    if retention.dedup_ttl_ms == 0 {
        retention.dedup_ttl_ms = 1;
    }
    // Zero pending ttl drops retry state instantly and can starve in-flight
    // reliability guarantees under short backoff loops.
    if retention.pending_ttl_ms == 0 {
        retention.pending_ttl_ms = 1;
    }
    // Zero cleanup interval causes cleanup to run on every receive(), which can
    // become a self-inflicted backpressure hotspot under sustained ingress.
    if retention.cleanup_interval_ms == 0 {
        retention.cleanup_interval_ms = 1;
    }
    retention
}

impl<S: ReliabilityStore> ReliabilityEngine<S> {
    pub fn new(store: S, retry: RetryConfig) -> Self {
        Self::new_with_retention(store, retry, RetentionConfig::default())
    }

    pub fn new_with_retention(store: S, retry: RetryConfig, retention: RetentionConfig) -> Self {
        Self {
            store,
            retry: sanitize_retry_config(retry),
            retention: sanitize_retention_config(retention),
            last_cleanup_at_unix_ms: None,
            circuit_state: CircuitState::Closed,
            consecutive_retry_exhausted: 0,
            retry_exhausted_total: AtomicU64::new(0),
            circuit_open_total: AtomicU64::new(0),
            circuit_recovered_total: AtomicU64::new(0),
            collect_rr_cursor: 0,
        }
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_state
    }

    fn increment_atomic_saturating(counter: &AtomicU64) {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                return;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn increment_retry_exhausted_total(&self) {
        Self::increment_atomic_saturating(&self.retry_exhausted_total);
    }

    #[cfg(test)]
    fn retry_exhausted_total(&self) -> u64 {
        self.retry_exhausted_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn circuit_open_total(&self) -> u64 {
        self.circuit_open_total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn circuit_recovered_total(&self) -> u64 {
        self.circuit_recovered_total.load(Ordering::Relaxed)
    }
}

