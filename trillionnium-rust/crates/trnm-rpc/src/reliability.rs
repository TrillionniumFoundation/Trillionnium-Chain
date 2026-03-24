use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DedupKey {
    pub from: String,
    pub seq_or_nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliableMessage {
    pub from: String,
    #[serde(default)]
    pub chain_id: String,
    pub session_id: String,
    pub seq: Option<u64>,
    pub nonce: Option<u64>,
    #[serde(default)]
    pub msg_type: String,
    pub payload: String,
}

impl ReliableMessage {
    fn requires_strict_fields(&self) -> bool {
        let msg_type = self.msg_type.trim();
        matches!(
            msg_type,
            "TASK_ACCEPT"
                | "INPUT_CHUNK"
                | "RESULT_META"
                | "RESULT_POINTER"
                | "ACK"
                | "ERROR"
                | "CLOSE"
        )
    }
    pub fn dedup_key(&self) -> Option<DedupKey> {
        self.seq.or(self.nonce).map(|v| DedupKey {
            from: self.from.clone(),
            seq_or_nonce: v,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckCode {
    Accepted,
    Duplicate,
    BadRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub code: AckCode,
    pub ack_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingItem {
    pub ack_id: String,
    pub message: ReliableMessage,
    pub attempts: u32,
    pub created_at_unix_ms: u128,
    pub next_retry_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub pending: BTreeMap<String, PendingItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReliabilityStoreError {
    CapacityExceeded { detail: String },
    InvalidState { detail: String },
}

impl std::fmt::Display for ReliabilityStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityExceeded { detail } => write!(f, "capacity_exceeded: {detail}"),
            Self::InvalidState { detail } => write!(f, "invalid_state: {detail}"),
        }
    }
}

impl std::error::Error for ReliabilityStoreError {}

pub trait ReliabilityStore {
    fn get_session(&self, session_id: &str) -> Option<SessionState>;
    fn upsert_session(&mut self, session: SessionState);
    fn remove_session(&mut self, session_id: &str);
    fn list_session_ids(&self) -> Vec<String>;
    fn contains_dedup_key(&self, key: &DedupKey) -> bool;
    fn remember_dedup_key(&mut self, key: DedupKey);
    fn remember_dedup_key_with_ts(&mut self, key: DedupKey, _now_unix_ms: u128) {
        self.remember_dedup_key(key);
    }

    // Fallible hooks for stores that enforce quotas/consistency.
    fn try_remember_dedup_key_with_ts(
        &mut self,
        key: DedupKey,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        self.remember_dedup_key_with_ts(key, now_unix_ms);
        Ok(())
    }

    fn try_upsert_session_with_ts(
        &mut self,
        session: SessionState,
        _now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        self.upsert_session(session);
        Ok(())
    }

    fn forget_dedup_key(&mut self, _key: &DedupKey) {}

    fn should_remove_empty_session_immediately(&self) -> bool {
        true
    }

    fn cleanup_expired(&mut self, _now_unix_ms: u128, _retention: &RetentionConfig) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptySessionCleanupPolicy {
    RemoveImmediately,
    RetainForMs(u64),
    KeepForever,
}

#[derive(Debug, Clone)]
pub struct InMemoryReliabilityStoreConfig {
    pub max_sessions: Option<usize>,
    pub max_pending_per_session: Option<usize>,
    pub max_pending_total: Option<usize>,
    pub max_dedup_entries: Option<usize>,
    pub empty_session_cleanup: EmptySessionCleanupPolicy,
}

impl Default for InMemoryReliabilityStoreConfig {
    fn default() -> Self {
        Self {
            max_sessions: None,
            max_pending_per_session: None,
            max_pending_total: None,
            max_dedup_entries: None,
            empty_session_cleanup: EmptySessionCleanupPolicy::RemoveImmediately,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SessionMeta {
    last_touched_unix_ms: u128,
    empty_since_unix_ms: Option<u128>,
}

#[derive(Debug, Default)]
pub struct InMemoryReliabilityStore {
    sessions: HashMap<String, SessionState>,
    dedup: HashMap<DedupKey, u128>,
    meta: HashMap<String, SessionMeta>,
    config: InMemoryReliabilityStoreConfig,
}

impl InMemoryReliabilityStore {
    pub fn with_config(config: InMemoryReliabilityStoreConfig) -> Self {
        let config = sanitize_store_config(config);

        // Pre-size hot reliability maps from configured quotas to reduce allocator
        // churn during sustained ingress bursts. Caps are hints only; semantics are
        // unchanged when quotas are unset.
        let session_cap = config.max_sessions.unwrap_or(0);
        let dedup_cap = config
            .max_dedup_entries
            .or(config.max_pending_total)
            .unwrap_or(0);

        Self {
            sessions: HashMap::with_capacity(session_cap),
            dedup: HashMap::with_capacity(dedup_cap),
            meta: HashMap::with_capacity(session_cap),
            config,
        }
    }

    fn total_pending_items(&self) -> usize {
        self.sessions.values().map(|s| s.pending.len()).sum()
    }
}

fn sanitize_store_config(
    mut config: InMemoryReliabilityStoreConfig,
) -> InMemoryReliabilityStoreConfig {
    // Zeroed quotas create permanent capacity_exceeded responses for fresh ingress.
    // Clamp to a minimally live value so misconfigured operators retain recovery paths.
    fn clamp_zero(opt: Option<usize>) -> Option<usize> {
        opt.map(|v| v.max(1))
    }

    config.max_sessions = clamp_zero(config.max_sessions);
    config.max_pending_per_session = clamp_zero(config.max_pending_per_session);
    config.max_pending_total = clamp_zero(config.max_pending_total);
    config.max_dedup_entries = clamp_zero(config.max_dedup_entries);

    if let (Some(per_session), Some(total)) =
        (config.max_pending_per_session, config.max_pending_total)
    {
        // Keep per-session quota within the global cap so operators cannot configure
        // an impossible local limit that only manifests as avoidable global backpressure.
        config.max_pending_per_session = Some(per_session.min(total));
    }

    if let (Some(dedup), Some(total)) = (config.max_dedup_entries, config.max_pending_total) {
        // Keep dedup quota from exceeding the pending backlog envelope.
        config.max_dedup_entries = Some(dedup.min(total));
    }

    // Zero-duration retain windows collapse into effectively immediate cleanup,
    // which can jitter between retain/remove behavior across cleanup call sites.
    // Keep a 1ms floor so "retain" mode remains semantically distinct.
    if let EmptySessionCleanupPolicy::RetainForMs(0) = config.empty_session_cleanup {
        config.empty_session_cleanup = EmptySessionCleanupPolicy::RetainForMs(1);
    }

    config
}

impl ReliabilityStore for InMemoryReliabilityStore {
    fn get_session(&self, session_id: &str) -> Option<SessionState> {
        self.sessions.get(session_id).cloned()
    }

    fn upsert_session(&mut self, session: SessionState) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        self.meta.remove(session_id);
    }

    fn list_session_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.sessions.keys().cloned().collect();
        // Hot reliability polling commonly observes 0/1 active sessions.
        // Skip sort work there and keep deterministic ordering for larger sets.
        if ids.len() < 2 {
            return ids;
        }
        ids.sort_unstable();
        ids
    }

    fn contains_dedup_key(&self, key: &DedupKey) -> bool {
        self.dedup.contains_key(key)
    }

    fn remember_dedup_key(&mut self, key: DedupKey) {
        self.dedup.insert(key, 0);
    }

    fn remember_dedup_key_with_ts(&mut self, key: DedupKey, now_unix_ms: u128) {
        self.dedup.insert(key, now_unix_ms);
    }

    fn forget_dedup_key(&mut self, key: &DedupKey) {
        self.dedup.remove(key);
    }

    fn try_remember_dedup_key_with_ts(
        &mut self,
        key: DedupKey,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        if let Some(max) = self.config.max_dedup_entries {
            use std::collections::hash_map::Entry;
            let at_capacity = self.dedup.len() >= max;
            match self.dedup.entry(key) {
                Entry::Occupied(mut occupied) => {
                    occupied.insert(now_unix_ms);
                    return Ok(());
                }
                Entry::Vacant(vacant) => {
                    if at_capacity {
                        return Err(ReliabilityStoreError::CapacityExceeded {
                            detail: format!("dedup limit reached ({max})"),
                        });
                    }
                    vacant.insert(now_unix_ms);
                    return Ok(());
                }
            }
        }
        self.remember_dedup_key_with_ts(key, now_unix_ms);
        Ok(())
    }

    fn try_upsert_session_with_ts(
        &mut self,
        session: SessionState,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        let session_id = session.session_id.clone();
        // Reuse a single session lookup for both old pending size and new-session
        // detection. This path is hit on every ingress upsert under backpressure.
        let old_len_opt = self.sessions.get(&session_id).map(|s| s.pending.len());
        let old_len = old_len_opt.unwrap_or(0);
        let new_len = session.pending.len();
        let is_new_session = old_len_opt.is_none();

        if let Some(max) = self.config.max_sessions {
            if is_new_session && self.sessions.len() >= max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_per_session {
            if new_len > max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("pending per-session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_total {
            // Non-growing updates on an existing session cannot increase global
            // pending pressure; skip O(session_count) total scans on this hot path.
            if is_new_session || new_len > old_len {
                let total = self.total_pending_items();
                let projected = total.saturating_sub(old_len).saturating_add(new_len);
                if projected > max {
                    return Err(ReliabilityStoreError::CapacityExceeded {
                        detail: format!("pending total limit reached ({max})"),
                    });
                }
            }
        }

        let is_empty = session.pending.is_empty();
        self.sessions.insert(session_id.clone(), session);

        let meta = self.meta.entry(session_id).or_default();
        if now_unix_ms != 0 {
            meta.last_touched_unix_ms = now_unix_ms;
        }
        if is_empty {
            if now_unix_ms != 0 {
                meta.empty_since_unix_ms.get_or_insert(now_unix_ms);
            }
        } else {
            meta.empty_since_unix_ms = None;
        }

        Ok(())
    }

    fn should_remove_empty_session_immediately(&self) -> bool {
        matches!(
            self.config.empty_session_cleanup,
            EmptySessionCleanupPolicy::RemoveImmediately
        )
    }

    fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let dedup_cutoff = now_unix_ms.saturating_sub(retention.dedup_ttl_ms as u128);
        self.dedup
            .retain(|_, seen_at| *seen_at == 0 || *seen_at >= dedup_cutoff);

        let pending_cutoff = now_unix_ms.saturating_sub(retention.pending_ttl_ms as u128);

        let session_ids: Vec<String> = self.sessions.keys().cloned().collect();
        for sid in session_ids {
            let mut remove = false;
            if let Some(session) = self.sessions.get_mut(&sid) {
                session
                    .pending
                    .retain(|_, item| item.created_at_unix_ms >= pending_cutoff);

                if session.pending.is_empty() {
                    let meta = self.meta.entry(sid.clone()).or_default();
                    // mark_acked() updates sessions without an explicit timestamp.
                    // Reuse last_touched as a stable fallback so empty-session TTL
                    // reclaim is measured from the latest known activity rather than
                    // drifting by an extra cleanup interval.
                    meta.empty_since_unix_ms
                        .get_or_insert(if meta.last_touched_unix_ms != 0 {
                            meta.last_touched_unix_ms
                        } else {
                            now_unix_ms
                        });
                    remove = match self.config.empty_session_cleanup {
                        EmptySessionCleanupPolicy::RemoveImmediately => true,
                        EmptySessionCleanupPolicy::RetainForMs(ttl_ms) => meta
                            .empty_since_unix_ms
                            .is_some_and(|t| now_unix_ms.saturating_sub(t) >= ttl_ms as u128),
                        EmptySessionCleanupPolicy::KeepForever => false,
                    };
                } else if let Some(meta) = self.meta.get_mut(&sid) {
                    meta.last_touched_unix_ms = now_unix_ms;
                    meta.empty_since_unix_ms = None;
                }
            }
            if remove {
                self.sessions.remove(&sid);
                self.meta.remove(&sid);
            }
        }
    }
}

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

const MIN_FREE_INGRESS_BACKOFF_MS: u64 = 1;
const MIN_RETENTION_FLOOR_MS: u64 = 1;

fn sanitize_retry_config(mut retry: RetryConfig) -> RetryConfig {
    // Keep free-ingress retry pacing on a strictly positive floor so malformed
    // configs cannot collapse backoff/circuit timing into immediate hot loops.
    retry.base_backoff_ms = retry.base_backoff_ms.max(MIN_FREE_INGRESS_BACKOFF_MS);

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
    if retry.circuit_open_ms < retry.base_backoff_ms {
        // Enforce the base floor for clearly undersized windows.
        retry.circuit_open_ms = retry.base_backoff_ms;
    } else if retry.circuit_breaker_threshold > 1 && retry.circuit_open_ms < retry.max_backoff_ms {
        // Multi-failure circuits are more likely to experience retry storms;
        // lift windows below the retry ceiling to the configured max backoff
        // so recovery cannot re-enter while long-tail retries are still active.
        retry.circuit_open_ms = retry.max_backoff_ms;
    }
    retry
}

fn sanitize_retention_config(
    mut retention: RetentionConfig,
    retry: &RetryConfig,
) -> RetentionConfig {
    // Zero dedup ttl disables idempotency memory and allows immediate duplicate
    // replays under concurrent ingress. Keep a shared 1ms floor so dedup remains active.
    if retention.dedup_ttl_ms == 0 {
        retention.dedup_ttl_ms = MIN_RETENTION_FLOOR_MS;
    }
    // Zero pending ttl drops retry state instantly and can starve in-flight
    // reliability guarantees under short backoff loops. Keep pending state alive
    // for at least one positive retry window so sponsor/free-ingress accounting
    // cannot evaporate before the next eligible retry boundary.
    if retention.pending_ttl_ms == 0 {
        retention.pending_ttl_ms = retry.max_backoff_ms.max(MIN_RETENTION_FLOOR_MS);
    } else if retention.pending_ttl_ms < retry.base_backoff_ms {
        // Keep explicitly configured windows that are smaller than a single retry
        // period aligned with the same retry ceiling policy as in circuit-open
        // behavior.
        retention.pending_ttl_ms = retry.max_backoff_ms;
    }
    // Zero cleanup interval causes cleanup to run on every receive(), which can
    // become a self-inflicted backpressure hotspot under sustained ingress.
    if retention.cleanup_interval_ms == 0 {
        retention.cleanup_interval_ms = MIN_RETENTION_FLOOR_MS;
    }

    let max_safe_cleanup_interval_ms = retention
        .dedup_ttl_ms
        .min(retention.pending_ttl_ms)
        .max(MIN_RETENTION_FLOOR_MS);
    if retention.cleanup_interval_ms > max_safe_cleanup_interval_ms {
        // Keep cleanup cadence inside both retention windows so stale dedup/pending
        // state cannot outlive its configured sponsor/free-ingress accounting bounds
        // by an entire oversized cleanup interval. Preserve the shared positive floor
        // even if future retention sanitization order changes.
        retention.cleanup_interval_ms = max_safe_cleanup_interval_ms;
    }

    retention
}

impl<S: ReliabilityStore> ReliabilityEngine<S> {
    pub fn new(store: S, retry: RetryConfig) -> Self {
        Self::new_with_retention(store, retry, RetentionConfig::default())
    }

    pub fn new_with_retention(store: S, retry: RetryConfig, retention: RetentionConfig) -> Self {
        let retry = sanitize_retry_config(retry);
        let retention = sanitize_retention_config(retention, &retry);

        Self {
            store,
            retry,
            retention,
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

    pub fn receive(&mut self, msg: ReliableMessage, now_unix_ms: u128) -> Ack {
        self.maybe_cleanup(now_unix_ms);

        if msg.chain_id.trim().is_empty() {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "missing chain_id".to_string(),
            };
        }
        if msg.from.trim().is_empty() {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "missing from".to_string(),
            };
        }
        if msg.session_id.trim().is_empty() {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "missing session_id".to_string(),
            };
        }
        // Replay/auth hardening: reject non-canonical identifiers with
        // surrounding whitespace so equivalent principals/namespaces cannot
        // bypass dedup domains by string-shape variance.
        if !is_canonical_identifier(&msg.chain_id)
            || !is_canonical_identifier(&msg.from)
            || !is_canonical_identifier(&msg.session_id)
        {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "non-canonical identifier".to_string(),
            };
        }
        // Gate hardening: preserve a single canonical msg_type namespace so
        // strict-field routing and replay domains cannot diverge by padding
        // or case-variant aliases.
        if !msg.msg_type.is_empty() && !is_canonical_msg_type(&msg.msg_type) {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "non-canonical msg_type".to_string(),
            };
        }
        if msg.requires_strict_fields() && msg.seq.is_none() {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "missing seq".to_string(),
            };
        }
        if msg.seq.is_some() && msg.nonce.is_some() {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "ambiguous seq/nonce".to_string(),
            };
        }

        let Some(dedup_key) = msg.dedup_key() else {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "missing seq/nonce".to_string(),
            };
        };
        if dedup_key.seq_or_nonce == 0 {
            return Ack {
                code: AckCode::BadRequest,
                ack_id: "ack_invalid".to_string(),
                detail: "invalid zero seq/nonce".to_string(),
            };
        }

        let ack_id = format!("ack_{}_{}", dedup_key.from, dedup_key.seq_or_nonce);
        if self.store.contains_dedup_key(&dedup_key) {
            return Ack {
                code: AckCode::Duplicate,
                ack_id,
                detail: "already processed".to_string(),
            };
        }

        if let Err(e) = self
            .store
            .try_remember_dedup_key_with_ts(dedup_key.clone(), now_unix_ms)
        {
            return Ack {
                code: AckCode::BadRequest,
                ack_id,
                detail: format!("store_rejected: {e}"),
            };
        }

        let mut session = self
            .store
            .get_session(&msg.session_id)
            .unwrap_or_else(|| SessionState {
                session_id: msg.session_id.clone(),
                pending: BTreeMap::new(),
            });

        // Guard against dedup TTL rollover while retry state is still pending.
        // A replay of the same ack_id must not reset attempts/backoff and gain
        // unfair retry priority under sustained ingress.
        if session.pending.contains_key(&ack_id) {
            return Ack {
                code: AckCode::Duplicate,
                ack_id,
                detail: "already pending".to_string(),
            };
        }

        session.pending.insert(
            ack_id.clone(),
            PendingItem {
                ack_id: ack_id.clone(),
                message: msg,
                attempts: 0,
                created_at_unix_ms: now_unix_ms,
                next_retry_at_unix_ms: now_unix_ms
                    .saturating_add(self.retry.base_backoff_ms as u128),
            },
        );

        if let Err(e) = self.store.try_upsert_session_with_ts(session, now_unix_ms) {
            self.store.forget_dedup_key(&dedup_key);
            return Ack {
                code: AckCode::BadRequest,
                ack_id,
                detail: format!("store_rejected: {e}"),
            };
        }

        Ack {
            code: AckCode::Accepted,
            ack_id,
            detail: "accepted".to_string(),
        }
    }

    pub fn mark_acked(&mut self, session_id: &str, ack_id: &str) -> bool {
        self.mark_acked_at(session_id, ack_id, current_unix_ms())
    }

    fn mark_acked_at(&mut self, session_id: &str, ack_id: &str, now_unix_ms: u128) -> bool {
        let Some(mut session) = self.store.get_session(session_id) else {
            return false;
        };
        let removed = session.pending.remove(ack_id).is_some();
        if session.pending.is_empty() && self.store.should_remove_empty_session_immediately() {
            self.store.remove_session(session_id);
        } else if self
            .store
            .try_upsert_session_with_ts(session, now_unix_ms)
            .is_err()
        {
            return false;
        }
        removed
    }

    fn advance_collect_rr_cursor(&mut self, session_count: usize) -> usize {
        let start = self.collect_rr_cursor % session_count;
        // Single-session fast path: keep cursor pinned to zero so hot retry loops
        // avoid redundant wrapping/modulo churn while preserving semantics.
        if session_count == 1 {
            self.collect_rr_cursor = 0;
        } else {
            // Harden against pathological/corrupted cursor values in long-running
            // processes and debug builds: wrapping increment avoids usize overflow
            // panic while preserving modulo-based round-robin semantics.
            self.collect_rr_cursor = self.collect_rr_cursor.wrapping_add(1) % session_count;
        }
        start
    }

    pub fn collect_due_retries(&mut self, now_unix_ms: u128) -> Vec<PendingItem> {
        self.maybe_cleanup(now_unix_ms);
        self.maybe_recover_circuit(now_unix_ms);

        if matches!(self.circuit_state, CircuitState::Open { .. }) {
            return Vec::new();
        }

        // Throughput hot-path: pre-allocate to the global dispatch cap so saturated
        // retry rounds avoid incremental Vec growth/realloc churn.
        let mut out = Vec::with_capacity(MAX_DUE_RETRIES_PER_COLLECT);
        let mut exhausted_in_this_round = 0u32;
        let session_ids = self.store.list_session_ids();
        let session_count = session_ids.len();

        if session_count == 0 {
            // Idle-cycle self-heal: keep cursor anchored so the first session after
            // a full drain starts from deterministic index 0 rather than carrying
            // stale high values across long idle gaps.
            self.collect_rr_cursor = 0;
            self.on_retry_round_finished(exhausted_in_this_round, now_unix_ms);
            return out;
        }

        let start = self.advance_collect_rr_cursor(session_count);

        for offset in 0..session_count {
            if out.len() >= MAX_DUE_RETRIES_PER_COLLECT {
                break;
            }

            let sid = &session_ids[(start + offset) % session_count];
            let Some(mut session) = self.store.get_session(sid) else {
                continue;
            };

            let mut dispatched_for_session = 0usize;
            let mut due_ack_ids = Vec::with_capacity(MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT);

            // Collect only as many due keys as we can dispatch in this round. This
            // avoids full-map retain scans on hot sessions once per-session/global
            // dispatch budgets are exhausted.
            for (ack_id, item) in &session.pending {
                if out.len() >= MAX_DUE_RETRIES_PER_COLLECT {
                    break;
                }
                if dispatched_for_session >= MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT {
                    break;
                }
                if item.next_retry_at_unix_ms > now_unix_ms {
                    continue;
                }
                due_ack_ids.push(ack_id.clone());
                dispatched_for_session = dispatched_for_session.saturating_add(1);
            }

            let mut exhausted_ack_ids = Vec::new();
            for ack_id in due_ack_ids {
                let Some(item) = session.pending.get_mut(&ack_id) else {
                    continue;
                };

                if item.attempts >= self.retry.max_attempts {
                    exhausted_in_this_round = exhausted_in_this_round.saturating_add(1);
                    eprintln!(
                        "[reliability] drop pending after max_attempts ack_id={} attempts={}",
                        ack_id, item.attempts
                    );
                    self.increment_retry_exhausted_total();
                    exhausted_ack_ids.push(ack_id);
                    continue;
                }

                item.attempts = item.attempts.saturating_add(1);
                let delay = exp_backoff_ms(
                    self.retry.base_backoff_ms,
                    self.retry.max_backoff_ms,
                    item.attempts,
                );
                item.next_retry_at_unix_ms = now_unix_ms.saturating_add(delay as u128);
                out.push(item.clone());
            }

            for ack_id in exhausted_ack_ids {
                session.pending.remove(&ack_id);
            }

            if session.pending.is_empty() && self.store.should_remove_empty_session_immediately() {
                self.store.remove_session(sid);
            } else if let Err(e) = self.store.try_upsert_session_with_ts(session, now_unix_ms) {
                // Fail closed on persistence errors: keeping a stale in-memory retry
                // view can repeatedly re-dispatch the same due item and amplify load.
                eprintln!(
                    "[reliability] drop session after failed retry-state persist sid={} err={}",
                    sid, e
                );
                self.store.remove_session(sid);
            }
        }

        self.on_retry_round_finished(exhausted_in_this_round, now_unix_ms);
        out
    }

    fn on_retry_round_finished(&mut self, exhausted_count: u32, now_unix_ms: u128) {
        if exhausted_count == 0 {
            self.consecutive_retry_exhausted = 0;
            return;
        }

        self.consecutive_retry_exhausted = self
            .consecutive_retry_exhausted
            .saturating_add(exhausted_count);

        if self.consecutive_retry_exhausted >= self.retry.circuit_breaker_threshold
            && !matches!(self.circuit_state, CircuitState::Open { .. })
        {
            let until_unix_ms = now_unix_ms.saturating_add(self.retry.circuit_open_ms as u128);
            self.circuit_state = CircuitState::Open { until_unix_ms };
            eprintln!(
                "[reliability] circuit open exhausted={} threshold={} until={}",
                self.consecutive_retry_exhausted,
                self.retry.circuit_breaker_threshold,
                until_unix_ms
            );
            Self::increment_atomic_saturating(&self.circuit_open_total);
        }
    }

    fn maybe_recover_circuit(&mut self, now_unix_ms: u128) {
        if let CircuitState::Open { until_unix_ms } = self.circuit_state {
            if now_unix_ms >= until_unix_ms {
                self.circuit_state = CircuitState::Closed;
                self.consecutive_retry_exhausted = 0;
                eprintln!("[reliability] circuit recovered at {}", now_unix_ms);
                Self::increment_atomic_saturating(&self.circuit_recovered_total);
            }
        }
    }

    fn maybe_cleanup(&mut self, now_unix_ms: u128) {
        let due = self.last_cleanup_at_unix_ms.is_none_or(|last| {
            now_unix_ms.saturating_sub(last) >= self.retention.cleanup_interval_ms as u128
        });
        if due {
            self.store.cleanup_expired(now_unix_ms, &self.retention);
            self.last_cleanup_at_unix_ms = Some(now_unix_ms);
        }
    }
}

const MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT: usize = 64;
const MAX_DUE_RETRIES_PER_COLLECT: usize = 256;

fn is_canonical_identifier(value: &str) -> bool {
    if value.trim() != value {
        return false;
    }

    !value
        .as_bytes()
        .iter()
        .any(|b| b.is_ascii_control() || *b == 0x7f)
}

fn is_canonical_msg_type(msg_type: &str) -> bool {
    if !is_canonical_identifier(msg_type) {
        return false;
    }

    !msg_type.as_bytes().iter().any(|b| b.is_ascii_lowercase())
}

fn exp_backoff_ms(base: u64, max: u64, attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(20);
    let factor = 1u64 << shift;
    base.saturating_mul(factor).min(max)
}

fn current_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityStoreMode {
    Sqlite,
    Memory,
}

impl ReliabilityStoreMode {
    pub fn from_env() -> Self {
        let mode = std::env::var("RELIABILITY_STORE")
            .ok()
            .and_then(|raw| normalized_env_path(&raw).map(|v| v.to_ascii_lowercase()))
            .unwrap_or_else(|| "sqlite".to_string());

        match mode.as_str() {
            "memory" => Self::Memory,
            _ => Self::Sqlite,
        }
    }
}

fn normalized_env_path(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let starts_with_quote = trimmed.starts_with('"') || trimmed.starts_with('\'');
    let ends_with_quote = trimmed.ends_with('"') || trimmed.ends_with('\'');

    if trimmed.len() == 1 && (starts_with_quote || ends_with_quote) {
        return None;
    }

    // Treat mismatched leading/trailing quote wrappers as noisy malformed input.
    if starts_with_quote ^ ends_with_quote {
        return None;
    }
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        let mixed_quote_pair = (first == b'\'' && last == b'"') || (first == b'"' && last == b'\'');
        if mixed_quote_pair {
            return None;
        }
    }

    let quoted = trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')));

    let stripped = if quoted {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
    .trim();

    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

pub fn default_reliability_db_path() -> PathBuf {
    if let Ok(path) = std::env::var("RELIABILITY_DB_PATH") {
        if let Some(normalized) = normalized_env_path(&path) {
            return PathBuf::from(normalized);
        }
    }

    if let Ok(xdg_state_home) = std::env::var("XDG_STATE_HOME") {
        if let Some(normalized) = normalized_env_path(&xdg_state_home) {
            return PathBuf::from(normalized)
                .join("trillionnium")
                .join("reliability.sqlite");
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if let Some(normalized) = normalized_env_path(&home) {
            return PathBuf::from(normalized)
                .join(".trillionnium")
                .join("reliability.sqlite");
        }
    }

    PathBuf::from("run/reliability/reliability.sqlite")
}

#[derive(Debug)]
pub struct SqliteReliabilityStore {
    conn: Connection,
    config: InMemoryReliabilityStoreConfig,
}

impl SqliteReliabilityStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ReliabilityStoreError> {
        Self::open_with_config(path, Self::default_persistent_config())
    }

    pub fn open_with_config(
        path: impl AsRef<std::path::Path>,
        config: InMemoryReliabilityStoreConfig,
    ) -> Result<Self, ReliabilityStoreError> {
        let conn = Connection::open(path).map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("open sqlite failed: {e}"),
        })?;
        Self::configure_connection(&conn)?;
        Self::apply_migrations(&conn)?;
        Ok(Self {
            conn,
            config: sanitize_store_config(config),
        })
    }

    fn default_persistent_config() -> InMemoryReliabilityStoreConfig {
        InMemoryReliabilityStoreConfig {
            max_sessions: Some(4_096),
            max_pending_per_session: Some(1_024),
            max_pending_total: Some(65_536),
            max_dedup_entries: Some(65_536),
            empty_session_cleanup: EmptySessionCleanupPolicy::RemoveImmediately,
        }
    }

    fn configure_connection(conn: &Connection) -> Result<(), ReliabilityStoreError> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;
            ",
        )
        .map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("configure sqlite pragmas failed: {e}"),
        })
    }

    fn apply_migrations(conn: &Connection) -> Result<(), ReliabilityStoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);",
        )
        .map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("init migration table failed: {e}"),
        })?;

        let current: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("read migration version failed: {e}"),
            })?;

        if current < 1 {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS reliability_sessions (
                    session_id TEXT PRIMARY KEY,
                    session_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reliability_dedup (
                    from_addr TEXT NOT NULL,
                    seq_or_nonce INTEGER NOT NULL,
                    seen_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY(from_addr, seq_or_nonce)
                );
                INSERT INTO schema_migrations(version) VALUES(1);
                ",
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("apply migration v1 failed: {e}"),
            })?;
        }

        if current < 2 {
            let _ = conn.execute(
                "ALTER TABLE reliability_sessions ADD COLUMN updated_at_unix_ms INTEGER NOT NULL DEFAULT 0",
                [],
            );
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version) VALUES(2)",
                [],
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("apply migration v2 failed: {e}"),
            })?;
        }

        Ok(())
    }

    fn total_pending_items(&self) -> usize {
        self.list_session_ids()
            .into_iter()
            .filter_map(|sid| self.get_session(&sid))
            .map(|session| session.pending.len())
            .sum()
    }

    fn cleanup_expired_sessions_only(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let pending_cutoff = now_unix_ms.saturating_sub(retention.pending_ttl_ms as u128);
        for sid in self.list_session_ids() {
            let Some(mut session) = self.get_session(&sid) else {
                continue;
            };
            session
                .pending
                .retain(|_, item| item.created_at_unix_ms >= pending_cutoff);
            if session.pending.is_empty() {
                self.remove_session(&sid);
            } else {
                let _ = self.try_upsert_session_with_ts(session, now_unix_ms);
            }
        }
    }
}

impl ReliabilityStore for SqliteReliabilityStore {
    fn get_session(&self, session_id: &str) -> Option<SessionState> {
        let payload: String = self
            .conn
            .query_row(
                "SELECT session_json FROM reliability_sessions WHERE session_id=?1",
                [session_id],
                |r| r.get(0),
            )
            .ok()?;
        serde_json::from_str::<SessionState>(&payload).ok()
    }

    fn upsert_session(&mut self, session: SessionState) {
        let _ = self.try_upsert_session_with_ts(session, 0);
    }

    fn remove_session(&mut self, session_id: &str) {
        let _ = self.conn.execute(
            "DELETE FROM reliability_sessions WHERE session_id=?1",
            [session_id],
        );
    }

    fn list_session_ids(&self) -> Vec<String> {
        let mut stmt = match self
            .conn
            .prepare("SELECT session_id FROM reliability_sessions ORDER BY session_id")
        {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |r| r.get::<_, String>(0)) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    fn contains_dedup_key(&self, key: &DedupKey) -> bool {
        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2)",
                rusqlite::params![key.from, key.seq_or_nonce],
                |r| r.get::<_, i64>(0),
            )
            .map(|exists| exists != 0)
            .unwrap_or(false)
    }

    fn remember_dedup_key(&mut self, key: DedupKey) {
        self.remember_dedup_key_with_ts(key, 0);
    }

    fn remember_dedup_key_with_ts(&mut self, key: DedupKey, now_unix_ms: u128) {
        let seen = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO reliability_dedup(from_addr, seq_or_nonce, seen_at_unix_ms)
             VALUES(?1, ?2, ?3)",
            rusqlite::params![key.from, key.seq_or_nonce, seen],
        );
    }

    fn try_remember_dedup_key_with_ts(
        &mut self,
        key: DedupKey,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        if let Some(max) = self.config.max_dedup_entries {
            let existing: i64 = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2)",
                    rusqlite::params![key.from, key.seq_or_nonce],
                    |r| r.get(0),
                )
                .map_err(|e| ReliabilityStoreError::InvalidState {
                    detail: format!("check dedup row failed: {e}"),
                })?;
            if existing == 0 {
                let count: i64 = self
                    .conn
                    .query_row("SELECT COUNT(*) FROM reliability_dedup", [], |r| r.get(0))
                    .map_err(|e| ReliabilityStoreError::InvalidState {
                        detail: format!("count dedup rows failed: {e}"),
                    })?;
                if usize::try_from(count).unwrap_or(usize::MAX) >= max {
                    return Err(ReliabilityStoreError::CapacityExceeded {
                        detail: format!("dedup limit reached ({max})"),
                    });
                }
            }
        }
        self.remember_dedup_key_with_ts(key, now_unix_ms);
        Ok(())
    }

    fn forget_dedup_key(&mut self, key: &DedupKey) {
        let _ = self.conn.execute(
            "DELETE FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2",
            rusqlite::params![key.from, key.seq_or_nonce],
        );
    }

    fn try_upsert_session_with_ts(
        &mut self,
        session: SessionState,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        let session_id = session.session_id.clone();
        let existing = self.get_session(&session_id);
        let old_len = existing.as_ref().map(|s| s.pending.len()).unwrap_or(0);
        let new_len = session.pending.len();
        let is_new_session = existing.is_none();

        if let Some(max) = self.config.max_sessions {
            if is_new_session && self.list_session_ids().len() >= max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_per_session {
            if new_len > max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("pending per-session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_total {
            // Keep sqlite parity with in-memory hot path: non-growing updates on an
            // existing session cannot increase global pending pressure, so skip
            // O(session_count) total scans under sustained ingress.
            if is_new_session || new_len > old_len {
                let total = self.total_pending_items();
                let projected = total.saturating_sub(old_len).saturating_add(new_len);
                if projected > max {
                    return Err(ReliabilityStoreError::CapacityExceeded {
                        detail: format!("pending total limit reached ({max})"),
                    });
                }
            }
        }

        let payload =
            serde_json::to_string(&session).map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("serialize session failed: {e}"),
            })?;
        let ts = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
        self.conn
            .execute(
                "INSERT INTO reliability_sessions(session_id, session_json, updated_at_unix_ms)
                 VALUES(?1, ?2, ?3)
                 ON CONFLICT(session_id) DO UPDATE SET
                   session_json=excluded.session_json,
                   updated_at_unix_ms=CASE
                     WHEN excluded.updated_at_unix_ms = 0 THEN reliability_sessions.updated_at_unix_ms
                     ELSE excluded.updated_at_unix_ms
                   END",
                rusqlite::params![session.session_id, payload, ts],
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("upsert session failed: {e}"),
            })?;
        Ok(())
    }

    fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let dedup_cutoff = now_unix_ms.saturating_sub(retention.dedup_ttl_ms as u128);
        let dedup_cutoff_i64 = i64::try_from(dedup_cutoff).unwrap_or(i64::MAX);
        let _ = self.conn.execute(
            "DELETE FROM reliability_dedup WHERE seen_at_unix_ms <> 0 AND seen_at_unix_ms < ?1",
            [dedup_cutoff_i64],
        );

        let pending_cutoff = now_unix_ms.saturating_sub(retention.pending_ttl_ms as u128);
        let pending_cutoff_i64 = i64::try_from(pending_cutoff).unwrap_or(i64::MAX);

        let mut stmt = match self.conn.prepare(
            "SELECT session_id, session_json, updated_at_unix_ms FROM reliability_sessions",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return,
        };
        let rows = match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        }) {
            Ok(rows) => rows,
            Err(_) => return,
        };

        let mut remove_ids = Vec::new();
        let mut updates = Vec::new();

        for row in rows.filter_map(Result::ok) {
            let (session_id, payload, updated_at_unix_ms) = row;
            let Ok(mut session) = serde_json::from_str::<SessionState>(&payload) else {
                remove_ids.push(session_id);
                continue;
            };

            let before_len = session.pending.len();
            session
                .pending
                .retain(|_, item| item.created_at_unix_ms >= pending_cutoff);

            if session.pending.is_empty() {
                if before_len != 0
                    || (updated_at_unix_ms != 0 && updated_at_unix_ms < pending_cutoff_i64)
                {
                    remove_ids.push(session_id);
                }
                continue;
            }

            if session.pending.len() != before_len {
                updates.push((
                    session_id,
                    session,
                    i64::try_from(now_unix_ms).unwrap_or(i64::MAX),
                ));
            }
        }
        drop(stmt);

        for session_id in remove_ids {
            let _ = self.conn.execute(
                "DELETE FROM reliability_sessions WHERE session_id=?1",
                [session_id],
            );
        }

        for (session_id, session, updated_at_unix_ms) in updates {
            if let Ok(payload) = serde_json::to_string(&session) {
                let _ = self.conn.execute(
                    "UPDATE reliability_sessions
                     SET session_json=?2, updated_at_unix_ms=?3
                     WHERE session_id=?1",
                    rusqlite::params![session_id, payload, updated_at_unix_ms],
                );
            }
        }
        self.cleanup_expired_sessions_only(now_unix_ms, retention);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn mk_msg(from: &str, session_id: &str, seq: u64) -> ReliableMessage {
        ReliableMessage {
            from: from.to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: session_id.to_string(),
            seq: Some(seq),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        }
    }

    #[derive(Default)]
    struct FailingUpsertStore {
        inner: InMemoryReliabilityStore,
        fail_upsert: bool,
    }

    impl ReliabilityStore for FailingUpsertStore {
        fn get_session(&self, session_id: &str) -> Option<SessionState> {
            self.inner.get_session(session_id)
        }

        fn upsert_session(&mut self, session: SessionState) {
            self.inner.upsert_session(session);
        }

        fn remove_session(&mut self, session_id: &str) {
            self.inner.remove_session(session_id);
        }

        fn list_session_ids(&self) -> Vec<String> {
            self.inner.list_session_ids()
        }

        fn contains_dedup_key(&self, key: &DedupKey) -> bool {
            self.inner.contains_dedup_key(key)
        }

        fn remember_dedup_key(&mut self, key: DedupKey) {
            self.inner.remember_dedup_key(key);
        }

        fn remember_dedup_key_with_ts(&mut self, key: DedupKey, now_unix_ms: u128) {
            self.inner.remember_dedup_key_with_ts(key, now_unix_ms);
        }

        fn try_upsert_session_with_ts(
            &mut self,
            session: SessionState,
            now_unix_ms: u128,
        ) -> Result<(), ReliabilityStoreError> {
            if self.fail_upsert {
                return Err(ReliabilityStoreError::InvalidState {
                    detail: "injected upsert failure".to_string(),
                });
            }
            self.inner.try_upsert_session_with_ts(session, now_unix_ms)
        }

        fn try_remember_dedup_key_with_ts(
            &mut self,
            key: DedupKey,
            now_unix_ms: u128,
        ) -> Result<(), ReliabilityStoreError> {
            self.inner.try_remember_dedup_key_with_ts(key, now_unix_ms)
        }

        fn forget_dedup_key(&mut self, key: &DedupKey) {
            self.inner.forget_dedup_key(key);
        }

        fn should_remove_empty_session_immediately(&self) -> bool {
            self.inner.should_remove_empty_session_immediately()
        }

        fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
            self.inner.cleanup_expired(now_unix_ms, retention);
        }
    }

    #[test]
    fn dedup_by_from_and_seq() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let a1 = engine.receive(mk_msg("alice", "s1", 7), 1_000);
        assert_eq!(a1.code, AckCode::Accepted);

        let a2 = engine.receive(mk_msg("alice", "s1", 7), 1_010);
        assert_eq!(a2.code, AckCode::Duplicate);

        let a3 = engine.receive(mk_msg("bob", "s1", 7), 1_020);
        assert_eq!(
            a3.code,
            AckCode::Accepted,
            "different from should not dedup"
        );
    }

    #[test]
    fn reject_missing_chain_id_or_seq_for_critical_message() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let mut missing_chain = mk_msg("alice", "s1", 1);
        missing_chain.chain_id.clear();
        let ack = engine.receive(missing_chain, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing chain_id"));

        let mut missing_from = mk_msg("alice", "s1", 1);
        missing_from.from = "   ".to_string();
        let ack = engine.receive(missing_from, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing from"));

        let mut missing_seq = mk_msg("alice", "s1", 1);
        missing_seq.seq = None;
        missing_seq.nonce = Some(99);
        let ack = engine.receive(missing_seq, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("missing seq"));
    }

    #[test]
    fn rejects_non_canonical_whitespace_wrapped_msg_type() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(77),
            msg_type: "  ACK  ".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn rejects_non_canonical_msg_type_case_variant_to_prevent_strict_field_bypass() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(77),
            msg_type: "ack".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn rejects_non_canonical_identifier_whitespace_to_prevent_replay_namespace_bypass() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: " alice ".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical identifier"));
    }

    #[test]
    fn rejects_non_canonical_identifier_with_control_chars() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice\n".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical identifier"));
    }

    #[test]
    fn rejects_non_canonical_identifier_with_ascii_del() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice\u{7f}".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: Some(1),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical identifier"));
    }

    #[test]
    fn rejects_non_canonical_msg_type_with_control_chars() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "alice".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "s1".to_string(),
            seq: None,
            nonce: Some(7),
            msg_type: "ACK\n".to_string(),
            payload: "ok".to_string(),
        };

        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("non-canonical msg_type"));
    }

    #[test]
    fn legacy_message_without_msg_type_allows_nonce_path() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "legacy-sender".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "legacy-session".to_string(),
            seq: None,
            nonce: Some(7),
            msg_type: String::new(),
            payload: "legacy".to_string(),
        };
        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::Accepted);
    }

    #[test]
    fn rejects_ambiguous_dual_seq_and_nonce_to_harden_replay_migration() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let msg = ReliableMessage {
            from: "legacy-sender".to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: "legacy-session".to_string(),
            seq: Some(7),
            nonce: Some(7),
            msg_type: String::new(),
            payload: "legacy".to_string(),
        };
        let ack = engine.receive(msg, 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("ambiguous seq/nonce"));
    }

    #[test]
    fn rejects_zero_seq_or_nonce_to_harden_replay_namespace() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let mut msg = mk_msg("alice", "s1", 0);
        let ack = engine.receive(msg.clone(), 1_000);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("invalid zero seq/nonce"));

        msg.seq = None;
        msg.nonce = Some(0);
        msg.msg_type = String::new();
        let ack = engine.receive(msg, 1_001);
        assert_eq!(ack.code, AckCode::BadRequest);
        assert!(ack.detail.contains("invalid zero seq/nonce"));
    }

    #[test]
    fn retry_uses_exponential_backoff() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);
        assert_eq!(first[0].ack_id, ack.ack_id);

        let second = engine.collect_due_retries(1_200);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 2);

        let third = engine.collect_due_retries(1_400);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].attempts, 3);
    }

    #[test]
    fn exp_backoff_saturates_without_overflow_for_large_bases() {
        // Regression guard for free-ingress throughput gates: malformed retry config
        // must not overflow into tiny delays that can trigger retry storms.
        let capped = exp_backoff_ms(u64::MAX - 7, u64::MAX - 3, 32);
        assert_eq!(capped, u64::MAX - 3);

        let exact_first_attempt = exp_backoff_ms(u64::MAX - 7, u64::MAX, 1);
        assert_eq!(exact_first_attempt, u64::MAX - 7);
    }

    #[test]
    fn reliability_engine_sanitizes_zero_retry_floor_for_free_ingress_boundaries() {
        let engine = ReliabilityEngine::new(
            InMemoryReliabilityStore::default(),
            RetryConfig {
                base_backoff_ms: 0,
                max_backoff_ms: 0,
                max_attempts: 0,
                circuit_breaker_threshold: 0,
                circuit_open_ms: 0,
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, MIN_FREE_INGRESS_BACKOFF_MS);
        assert_eq!(engine.retry.max_backoff_ms, MIN_FREE_INGRESS_BACKOFF_MS);
        assert_eq!(engine.retry.max_attempts, 1);
        assert_eq!(engine.retry.circuit_breaker_threshold, 1);
        assert_eq!(engine.retry.circuit_open_ms, MIN_FREE_INGRESS_BACKOFF_MS);
    }

    #[test]
    fn reliability_engine_clamps_circuit_open_window_to_retry_ceiling() {
        let engine = ReliabilityEngine::new(
            InMemoryReliabilityStore::default(),
            RetryConfig {
                base_backoff_ms: 5,
                max_backoff_ms: 80,
                max_attempts: 3,
                circuit_breaker_threshold: 2,
                circuit_open_ms: 7,
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, 5);
        assert_eq!(engine.retry.max_backoff_ms, 80);
        assert_eq!(engine.retry.circuit_open_ms, 80);
    }

    #[test]
    fn reliability_engine_sanitizes_zero_retention_floors() {
        let engine = ReliabilityEngine::new_with_retention(
            InMemoryReliabilityStore::default(),
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 0,
                pending_ttl_ms: 0,
                cleanup_interval_ms: 0,
            },
        );

        assert_eq!(engine.retention.dedup_ttl_ms, MIN_RETENTION_FLOOR_MS);
        assert_eq!(engine.retention.pending_ttl_ms, 10_000);
        assert_eq!(engine.retention.cleanup_interval_ms, MIN_RETENTION_FLOOR_MS);
    }

    #[test]
    fn reliability_engine_clamps_cleanup_interval_to_smallest_retention_window() {
        let engine = ReliabilityEngine::new_with_retention(
            InMemoryReliabilityStore::default(),
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 25,
                pending_ttl_ms: 10,
                cleanup_interval_ms: 250,
            },
        );

        assert_eq!(engine.retention.dedup_ttl_ms, 25);
        assert_eq!(engine.retention.pending_ttl_ms, 10_000);
        assert_eq!(engine.retention.cleanup_interval_ms, 25);
    }

    #[test]
    fn reliability_engine_clamps_pending_ttl_to_retry_ceiling() {
        let engine = ReliabilityEngine::new_with_retention(
            InMemoryReliabilityStore::default(),
            RetryConfig {
                base_backoff_ms: 25,
                max_backoff_ms: 250,
                max_attempts: 3,
                circuit_breaker_threshold: 2,
                circuit_open_ms: 250,
            },
            RetentionConfig {
                dedup_ttl_ms: 1_000,
                pending_ttl_ms: 10,
                cleanup_interval_ms: 500,
            },
        );

        assert_eq!(engine.retention.pending_ttl_ms, 250);
        assert_eq!(engine.retention.cleanup_interval_ms, 250);
    }

    #[test]
    fn reliability_engine_preserves_positive_cleanup_floor_when_one_retention_window_is_zero() {
        let engine = ReliabilityEngine::new_with_retention(
            InMemoryReliabilityStore::default(),
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 25,
                pending_ttl_ms: 0,
                cleanup_interval_ms: 250,
            },
        );

        assert_eq!(engine.retention.dedup_ttl_ms, 25);
        assert_eq!(engine.retention.pending_ttl_ms, 10_000);
        assert_eq!(engine.retention.cleanup_interval_ms, 25);
    }

    #[test]
    fn max_attempts_stops_retrying_and_drops_pending() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                max_attempts: 2,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);

        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);

        let second = engine.collect_due_retries(1_200);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 2);

        let third = engine.collect_due_retries(1_400);
        assert!(third.is_empty(), "must stop retrying after max_attempts");
        assert_eq!(engine.retry_exhausted_total(), 1);

        let store = engine.into_store();
        let session = store.get_session("s1");
        assert!(
            session.is_none(),
            "pending item should be dropped after max attempts"
        );

        assert_eq!(ack.ack_id, "ack_alice_1");
    }

    #[test]
    fn circuit_breaker_opens_and_recovers_after_window() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 800,
                max_attempts: 1,
                circuit_breaker_threshold: 1,
                circuit_open_ms: 300,
            },
        );

        engine.receive(mk_msg("alice", "s1", 1), 1_000);

        let first = engine.collect_due_retries(1_100);
        assert_eq!(first.len(), 1);
        assert_eq!(engine.circuit_state(), CircuitState::Closed);

        let exhausted_round = engine.collect_due_retries(1_200);
        assert!(exhausted_round.is_empty());
        assert_eq!(engine.retry_exhausted_total(), 1);
        assert_eq!(engine.circuit_open_total(), 1);
        assert_eq!(
            engine.circuit_state(),
            CircuitState::Open {
                until_unix_ms: 1_500
            }
        );

        engine.receive(mk_msg("bob", "s2", 1), 1_250);
        let blocked = engine.collect_due_retries(1_350);
        assert!(blocked.is_empty());

        let recovered = engine.collect_due_retries(1_550);
        assert_eq!(engine.circuit_state(), CircuitState::Closed);
        assert_eq!(engine.circuit_recovered_total(), 1);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].ack_id, "ack_bob_1");
    }

    #[test]
    fn mark_acked_removes_pending() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());
        let ack = engine.receive(mk_msg("alice", "sess", 3), 1_000);

        assert!(engine.mark_acked("sess", &ack.ack_id));

        let retries = engine.collect_due_retries(10_000);
        assert!(retries.is_empty());
    }

    #[test]
    fn cleanup_expires_dedup_and_accepts_again_after_ttl() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 100,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let first = engine.receive(mk_msg("alice", "s1", 9), 1_000);
        assert_eq!(first.code, AckCode::Accepted);

        let dup = engine.receive(mk_msg("alice", "s1", 9), 1_050);
        assert_eq!(dup.code, AckCode::Duplicate);

        // This test isolates dedup-TTL expiry after the original delivery has been
        // fully acknowledged. Pending retry state is covered separately below and
        // must still reject replays even after dedup memory ages out.
        assert!(engine.mark_acked("s1", &first.ack_id));

        let after_ttl = engine.receive(mk_msg("alice", "s1", 9), 1_101);
        assert_eq!(after_ttl.code, AckCode::Accepted);
    }

    #[test]
    fn cleanup_preserves_legacy_dedup_entries_without_timestamp() {
        let mut store = InMemoryReliabilityStore::default();
        let key = DedupKey {
            from: "legacy".to_string(),
            seq_or_nonce: 77,
        };
        store.remember_dedup_key(key.clone()); // seen_at=0 legacy path

        store.cleanup_expired(
            10_000,
            &RetentionConfig {
                dedup_ttl_ms: 100,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        assert!(
            store.contains_dedup_key(&key),
            "legacy seen_at=0 dedup entry should remain until rewritten with a timestamp"
        );
    }

    #[test]
    fn cleanup_drops_only_expired_pending_items() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig {
                base_backoff_ms: 100,
                max_backoff_ms: 1_000,
                ..RetryConfig::default()
            },
            RetentionConfig {
                dedup_ttl_ms: 10_000,
                pending_ttl_ms: 500,
                cleanup_interval_ms: 1,
            },
        );

        let old = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        let fresh = engine.receive(mk_msg("alice", "s1", 2), 1_300);

        let due = engine.collect_due_retries(1_499);
        assert_eq!(due.len(), 2, "before ttl cutoff both should stay");

        let due_after_cleanup = engine.collect_due_retries(1_600);
        assert_eq!(
            due_after_cleanup.len(),
            1,
            "expired pending must be removed"
        );
        assert_eq!(
            due_after_cleanup[0].ack_id, fresh.ack_id,
            "fresh item must remain"
        );
        assert_ne!(due_after_cleanup[0].ack_id, old.ack_id);
    }

    #[test]
    fn capacity_limit_returns_bad_request_with_detail() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_sessions: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let ok = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert_eq!(ok.code, AckCode::Accepted);

        let blocked = engine.receive(mk_msg("bob", "s2", 1), 1_001);
        assert_eq!(blocked.code, AckCode::BadRequest);
        assert!(blocked.detail.contains("capacity_exceeded"));
    }

    #[test]
    fn collect_due_retries_caps_per_session_to_reduce_hot_session_starvation() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        for seq in 1..=80 {
            let ack = engine.receive(mk_msg("alice", "hot", seq), 1_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        for seq in 1..=2 {
            let ack = engine.receive(mk_msg("bob", "cold", seq), 2_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }

        let first_round = engine.collect_due_retries(10_000);
        let hot_count = first_round
            .iter()
            .filter(|i| i.message.session_id == "hot")
            .count();
        let cold_count = first_round
            .iter()
            .filter(|i| i.message.session_id == "cold")
            .count();

        assert_eq!(hot_count, MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT);
        assert_eq!(cold_count, 2, "cold session should still make progress");

        let second_round = engine.collect_due_retries(10_002);
        let hot_count_second = second_round
            .iter()
            .filter(|i| i.message.session_id == "hot")
            .count();
        assert_eq!(
            hot_count_second, MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT,
            "hot session should stay bounded per collect cycle"
        );
    }

    #[test]
    fn collect_due_retries_applies_global_cap_and_rotates_start_session() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        // Keep each session small enough to avoid hitting per-session caps; this
        // isolates global-cap and round-robin behavior.
        for seq in 1..=100 {
            let ack = engine.receive(mk_msg("alice", "s-a", seq), 1_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        for seq in 1..=100 {
            let ack = engine.receive(mk_msg("bob", "s-b", seq), 2_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        for seq in 1..=100 {
            let ack = engine.receive(mk_msg("carol", "s-c", seq), 3_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        for seq in 1..=100 {
            let ack = engine.receive(mk_msg("dave", "s-d", seq), 4_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        for seq in 1..=100 {
            let ack = engine.receive(mk_msg("erin", "s-e", seq), 5_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }

        let first = engine.collect_due_retries(10_000);
        assert_eq!(
            first.len(),
            MAX_DUE_RETRIES_PER_COLLECT,
            "global cap should bound one collect cycle"
        );

        let first_front = first.first().expect("first batch not empty");
        assert_eq!(first_front.message.session_id, "s-a");

        let second = engine.collect_due_retries(10_001);
        assert_eq!(
            second.len(),
            MAX_DUE_RETRIES_PER_COLLECT,
            "global cap should remain stable across rounds"
        );

        let second_front = second.first().expect("second batch not empty");
        assert_eq!(
            second_front.message.session_id, "s-b",
            "round-robin session rotation should avoid fixed first-session bias"
        );
    }

    #[test]
    fn collect_due_retries_cursor_handles_session_churn_without_stalling_other_sessions() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        let hot_ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
        assert_eq!(hot_ack.code, AckCode::Accepted);
        let cold_ack = engine.receive(mk_msg("bob", "s-b", 1), 1_001);
        assert_eq!(cold_ack.code, AckCode::Accepted);

        let first = engine.collect_due_retries(2_000);
        assert_eq!(
            first.first().map(|i| i.message.session_id.as_str()),
            Some("s-a")
        );

        // Simulate session churn: one lane drains/acks fully while another lane remains hot.
        assert!(engine.mark_acked("s-a", &hot_ack.ack_id));

        let second = engine.collect_due_retries(2_001);
        assert_eq!(
            second.first().map(|i| i.message.session_id.as_str()),
            Some("s-b"),
            "round-robin cursor should rebase on the active session set"
        );
    }

    #[test]
    fn global_cap_round_robin_still_grants_new_cold_session_a_turn_next_cycle() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        // Start with one hot session so cursor is pinned to zero in the single-session path.
        for seq in 1..=(MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT as u64 + 8) {
            let ack = engine.receive(mk_msg("alice", "s-hot", seq), 1_000 + seq as u128);
            assert_eq!(ack.code, AckCode::Accepted);
        }
        let first = engine.collect_due_retries(2_000);
        assert_eq!(first.len(), MAX_DUE_RETRIES_PER_SESSION_PER_COLLECT);
        assert!(first.iter().all(|item| item.message.session_id == "s-hot"));

        // A new cold session should not be starved indefinitely by the global cap:
        // after one capped cycle, round-robin rotation must give it front-of-batch priority.
        let cold = engine.receive(mk_msg("bob", "s-cold", 1), 2_001);
        assert_eq!(cold.code, AckCode::Accepted);

        let second = engine.collect_due_retries(2_002);
        assert_eq!(
            second.first().map(|item| item.message.session_id.as_str()),
            Some("s-cold"),
            "new cold session should get first dispatch on the next collect cycle"
        );
    }

    #[test]
    fn collect_due_retries_single_session_keeps_cursor_stable_at_zero() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
        assert_eq!(ack.code, AckCode::Accepted);

        engine.collect_rr_cursor = usize::MAX;
        let first = engine.collect_due_retries(2_000);
        assert_eq!(first.len(), 1);
        assert_eq!(engine.collect_rr_cursor, 0);

        let second = engine.collect_due_retries(2_001);
        assert_eq!(second.len(), 1);
        assert_eq!(engine.collect_rr_cursor, 0);
    }

    #[test]
    fn collect_due_retries_cursor_wraps_without_overflow_panic() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        let ack_a = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
        let ack_b = engine.receive(mk_msg("bob", "s-b", 1), 1_001);
        assert_eq!(ack_a.code, AckCode::Accepted);
        assert_eq!(ack_b.code, AckCode::Accepted);

        engine.collect_rr_cursor = usize::MAX;

        let due = engine.collect_due_retries(2_000);
        assert_eq!(
            due.first().map(|i| i.message.session_id.as_str()),
            Some("s-b"),
            "wrapped cursor should still produce deterministic modulo rotation"
        );

        assert_eq!(engine.collect_rr_cursor, 0);
    }

    #[test]
    fn collect_due_retries_resets_cursor_after_idle_full_drain() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        let ack = engine.receive(mk_msg("alice", "s-a", 1), 1_000);
        assert_eq!(ack.code, AckCode::Accepted);

        engine.collect_rr_cursor = usize::MAX;
        assert!(engine.mark_acked("s-a", &ack.ack_id));

        let idle = engine.collect_due_retries(2_000);
        assert!(idle.is_empty());
        assert_eq!(
            engine.collect_rr_cursor, 0,
            "idle collect should reset stale cursor state"
        );

        let cold = engine.receive(mk_msg("bob", "s-b", 1), 2_001);
        assert_eq!(cold.code, AckCode::Accepted);
        let due = engine.collect_due_retries(2_002);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].message.session_id, "s-b");
    }

    #[test]
    fn collect_due_retries_drops_session_when_retry_state_persist_fails() {
        let mut store = FailingUpsertStore::default();
        store.fail_upsert = true;
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        // Seed one pending item while upsert failures are disabled.
        engine.store.fail_upsert = false;
        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert_eq!(ack.code, AckCode::Accepted);

        // Inject persistence failure for the collect/update pass.
        engine.store.fail_upsert = true;
        let due = engine.collect_due_retries(2_000);
        assert_eq!(due.len(), 1, "first due retry still dispatches once");

        let store = engine.into_store();
        assert!(
            store.get_session("s1").is_none(),
            "failed retry-state persist should drop session to avoid retry storms"
        );
    }

    #[test]
    fn dedup_quota_limit_rejects_fresh_ingress_without_breaking_duplicate_ack_path() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_dedup_entries: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new(store, RetryConfig::default());

        let first = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert_eq!(first.code, AckCode::Accepted);

        // New dedup domains should be backpressured once quota is full.
        let blocked = engine.receive(mk_msg("bob", "s2", 9), 1_001);
        assert_eq!(blocked.code, AckCode::BadRequest);
        assert!(blocked.detail.contains("dedup limit reached (1)"));

        // Existing dedup domains must still resolve to Duplicate rather than
        // quota errors so callers keep idempotent semantics under pressure.
        let duplicate = engine.receive(mk_msg("alice", "s1", 1), 1_002);
        assert_eq!(duplicate.code, AckCode::Duplicate);
        assert_eq!(duplicate.ack_id, first.ack_id);
    }

    #[test]
    fn dedup_ttl_expiry_does_not_reset_existing_pending_retry_state() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig {
                base_backoff_ms: 10,
                max_backoff_ms: 10,
                ..RetryConfig::default()
            },
            RetentionConfig {
                dedup_ttl_ms: 1,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let first = engine.receive(mk_msg("alice", "s1", 7), 1_000);
        assert_eq!(first.code, AckCode::Accepted);

        // Dedup memory expires, but retry state is still pending in-session.
        engine.maybe_cleanup(1_010);
        let replay = engine.receive(mk_msg("alice", "s1", 7), 1_011);
        assert_eq!(replay.code, AckCode::Duplicate);
        assert_eq!(replay.detail, "already pending");

        let store = engine.into_store();
        let session = store.get_session("s1").expect("session should exist");
        assert_eq!(
            session.pending.len(),
            1,
            "replay must not overwrite pending state"
        );

        let item = session
            .pending
            .get(&first.ack_id)
            .expect("pending item should keep original ack_id");
        assert_eq!(item.created_at_unix_ms, 1_000);
        assert_eq!(item.attempts, 0);
    }

    #[test]
    fn dedup_quota_allows_refreshing_existing_key_timestamp_at_capacity() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_dedup_entries: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let key = DedupKey {
            from: "alice".to_string(),
            seq_or_nonce: 7,
        };

        assert!(store
            .try_remember_dedup_key_with_ts(key.clone(), 1_000)
            .is_ok());
        assert!(store
            .try_remember_dedup_key_with_ts(key.clone(), 2_000)
            .is_ok());

        let blocked = store.try_remember_dedup_key_with_ts(
            DedupKey {
                from: "bob".to_string(),
                seq_or_nonce: 8,
            },
            2_001,
        );
        assert!(matches!(
            blocked,
            Err(ReliabilityStoreError::CapacityExceeded { .. })
        ));

        assert_eq!(store.dedup.get(&key), Some(&2_000));
    }

    #[test]
    fn empty_session_retained_until_cleanup_ttl() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(200),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 10_000,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert!(engine.mark_acked_at("s1", &ack.ack_id, 1_000));

        // Empty session should still exist before its empty-session ttl elapses.
        let due = engine.collect_due_retries(1_100);
        assert!(due.is_empty());

        let store = engine.into_store();
        assert!(store.get_session("s1").is_some());
    }

    #[test]
    fn empty_session_cleanup_ttl_eventually_reclaims_idle_session() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(200),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 10_000,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert!(engine.mark_acked_at("s1", &ack.ack_id, 1_000));

        // Trigger cleanup at/after TTL so retained empty sessions do not linger
        // and consume quota under prolonged idle periods.
        let due = engine.collect_due_retries(1_201);
        assert!(due.is_empty());

        let store = engine.into_store();
        assert!(store.get_session("s1").is_none());
    }

    #[test]
    fn empty_session_cleanup_ttl_starts_at_ack_time_not_original_ingress_time() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(200),
            ..InMemoryReliabilityStoreConfig::default()
        });
        let mut engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 10_000,
                pending_ttl_ms: 10_000,
                cleanup_interval_ms: 1,
            },
        );

        let ack = engine.receive(mk_msg("alice", "s1", 1), 1_000);
        assert!(engine.mark_acked_at("s1", &ack.ack_id, 1_500));

        let due_before_ttl = engine.collect_due_retries(1_699);
        assert!(due_before_ttl.is_empty());
        assert!(engine.store.get_session("s1").is_some());

        let due_after_ttl = engine.collect_due_retries(1_700);
        assert!(due_after_ttl.is_empty());
        assert!(engine.store.get_session("s1").is_none());
    }

    #[test]
    fn concurrent_receive_preserves_dedup() {
        let engine = Arc::new(Mutex::new(ReliabilityEngine::new(
            InMemoryReliabilityStore::default(),
            RetryConfig::default(),
        )));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let e = Arc::clone(&engine);
            handles.push(thread::spawn(move || {
                let mut g = e.lock().expect("lock");
                g.receive(mk_msg("alice", "sess", 42), 1_000).code
            }));
        }

        let mut accepted = 0;
        let mut duplicate = 0;
        for h in handles {
            match h.join().expect("thread join") {
                AckCode::Accepted => accepted += 1,
                AckCode::Duplicate => duplicate += 1,
                other => panic!("unexpected ack: {other:?}"),
            }
        }

        assert_eq!(accepted, 1);
        assert_eq!(duplicate, 15);
    }

    #[test]
    fn in_memory_store_lists_sessions_in_stable_sorted_order() {
        let mut store = InMemoryReliabilityStore::default();
        store.upsert_session(SessionState {
            session_id: "s-b".to_string(),
            pending: BTreeMap::new(),
        });
        store.upsert_session(SessionState {
            session_id: "s-a".to_string(),
            pending: BTreeMap::new(),
        });
        store.upsert_session(SessionState {
            session_id: "s-c".to_string(),
            pending: BTreeMap::new(),
        });

        assert_eq!(
            store.list_session_ids(),
            vec!["s-a".to_string(), "s-b".to_string(), "s-c".to_string()]
        );
    }

    #[test]
    fn reliability_store_mode_defaults_to_sqlite_and_keeps_memory_override() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::remove_var("RELIABILITY_STORE");
        assert_eq!(
            ReliabilityStoreMode::from_env(),
            ReliabilityStoreMode::Sqlite
        );

        std::env::set_var("RELIABILITY_STORE", "memory");
        assert_eq!(
            ReliabilityStoreMode::from_env(),
            ReliabilityStoreMode::Memory
        );

        // Noisy quoted values are common in env templating; accept canonical
        // mode tokens after trimming quote wrappers.
        std::env::set_var("RELIABILITY_STORE", "  'memory'  ");
        assert_eq!(
            ReliabilityStoreMode::from_env(),
            ReliabilityStoreMode::Memory
        );

        // Mismatched quotes are malformed and should fail closed to sqlite.
        std::env::set_var("RELIABILITY_STORE", "\"memory'");
        assert_eq!(
            ReliabilityStoreMode::from_env(),
            ReliabilityStoreMode::Sqlite
        );

        std::env::remove_var("RELIABILITY_STORE");
    }

    #[test]
    fn reliability_db_path_prefers_explicit_env_and_has_stable_fallback() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("RELIABILITY_DB_PATH", "/tmp/explicit-reliability.sqlite");
        assert_eq!(
            default_reliability_db_path(),
            PathBuf::from("/tmp/explicit-reliability.sqlite")
        );

        std::env::set_var(
            "RELIABILITY_DB_PATH",
            "  \"/tmp/quoted-reliability.sqlite\"  ",
        );
        assert_eq!(
            default_reliability_db_path(),
            PathBuf::from("/tmp/quoted-reliability.sqlite")
        );

        // Mismatched quote wrappers are malformed and must not leak literal
        // quote characters into filesystem paths.
        std::env::set_var("RELIABILITY_DB_PATH", "\"/tmp/mixed.sqlite'");
        std::env::set_var("XDG_STATE_HOME", "/tmp/state-home");
        assert_eq!(
            default_reliability_db_path(),
            PathBuf::from("/tmp/state-home/trillionnium/reliability.sqlite")
        );

        // Noisy single-quote values should be treated as invalid input and
        // fall back safely instead of slicing panic.
        std::env::set_var("RELIABILITY_DB_PATH", "'");
        std::env::remove_var("XDG_STATE_HOME");
        std::env::remove_var("HOME");
        assert_eq!(
            default_reliability_db_path(),
            PathBuf::from("run/reliability/reliability.sqlite")
        );

        std::env::remove_var("RELIABILITY_DB_PATH");
        std::env::remove_var("XDG_STATE_HOME");
        std::env::remove_var("HOME");
        assert_eq!(
            default_reliability_db_path(),
            PathBuf::from("run/reliability/reliability.sqlite")
        );
    }

    #[test]
    fn sqlite_store_open_applies_resilience_pragmas() {
        let unique = format!(
            "trnm-reliability-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix epoch")
                .as_nanos()
        );
        let db_path = std::env::temp_dir().join(unique);

        let store = SqliteReliabilityStore::open(&db_path).expect("open sqlite store");

        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("query journal_mode");
        assert_eq!(mode.to_ascii_lowercase(), "wal");

        let busy_timeout_ms: i64 = store
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("query busy_timeout");
        assert_eq!(busy_timeout_ms, 5_000);

        drop(store);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("sqlite-shm"));
    }

    #[test]
    fn store_config_clamps_zero_dedup_quota_to_keep_one_idempotency_slot_live() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_dedup_entries: Some(0),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let key1 = DedupKey {
            from: "alice".to_string(),
            seq_or_nonce: 1,
        };
        let key2 = DedupKey {
            from: "bob".to_string(),
            seq_or_nonce: 1,
        };

        assert!(store.try_remember_dedup_key_with_ts(key1, 1).is_ok());
        let err = store
            .try_remember_dedup_key_with_ts(key2, 2)
            .expect_err("second unique key should hit clamped quota");
        assert!(matches!(
            err,
            ReliabilityStoreError::CapacityExceeded { .. }
        ));
    }

    #[test]
    fn store_config_raises_dedup_quota_to_cover_pending_total_window() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_pending_total: Some(2),
            max_dedup_entries: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let key1 = DedupKey {
            from: "alice".to_string(),
            seq_or_nonce: 1,
        };
        let key2 = DedupKey {
            from: "bob".to_string(),
            seq_or_nonce: 1,
        };
        let key3 = DedupKey {
            from: "carol".to_string(),
            seq_or_nonce: 1,
        };

        assert!(store.try_remember_dedup_key_with_ts(key1, 1).is_ok());
        let err = store.try_remember_dedup_key_with_ts(key2, 2).expect_err(
            "second unique key should still be capped by dedup at pending window floor",
        );
        assert!(matches!(
            err,
            ReliabilityStoreError::CapacityExceeded { .. }
        ));
        let err = store
            .try_remember_dedup_key_with_ts(key3, 3)
            .expect_err("third unique key should also hit same dedup floor");
        assert!(matches!(
            err,
            ReliabilityStoreError::CapacityExceeded { .. }
        ));
    }

    #[test]
    fn store_config_clamps_zero_session_limit_to_preserve_forward_progress() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_sessions: Some(0),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let session = SessionState {
            session_id: "s1".to_string(),
            pending: BTreeMap::new(),
        };

        assert!(store.try_upsert_session_with_ts(session, 1).is_ok());
        assert_eq!(store.list_session_ids(), vec!["s1".to_string()]);
    }

    #[test]
    fn store_config_clamps_per_session_pending_quota_to_global_total_cap() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_pending_per_session: Some(5),
            max_pending_total: Some(2),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let mk_pending = |ack_id: &str| PendingItem {
            ack_id: ack_id.to_string(),
            message: ReliableMessage {
                from: "alice".to_string(),
                chain_id: "trnm-testnet".to_string(),
                session_id: "s1".to_string(),
                seq: Some(1),
                nonce: None,
                msg_type: "INPUT_CHUNK".to_string(),
                payload: "x".to_string(),
            },
            attempts: 0,
            created_at_unix_ms: 1,
            next_retry_at_unix_ms: 1,
        };

        let mut two_pending = BTreeMap::new();
        two_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
        two_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
        let two = SessionState {
            session_id: "s1".to_string(),
            pending: two_pending,
        };
        assert!(store.try_upsert_session_with_ts(two, 1).is_ok());

        let mut three_pending = BTreeMap::new();
        three_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
        three_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
        three_pending.insert("ack-3".to_string(), mk_pending("ack-3"));
        let three = SessionState {
            session_id: "s1".to_string(),
            pending: three_pending,
        };

        let err = store
            .try_upsert_session_with_ts(three, 2)
            .expect_err("per-session quota should be clamped to global total cap");
        assert!(matches!(
            err,
            ReliabilityStoreError::CapacityExceeded { .. }
        ));
    }

    #[test]
    fn store_config_clamps_zero_pending_quotas_to_keep_ingress_live() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_pending_per_session: Some(0),
            max_pending_total: Some(0),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let mk_pending = |ack_id: &str| PendingItem {
            ack_id: ack_id.to_string(),
            message: ReliableMessage {
                from: "alice".to_string(),
                chain_id: "trnm-testnet".to_string(),
                session_id: "s1".to_string(),
                seq: Some(1),
                nonce: None,
                msg_type: "INPUT_CHUNK".to_string(),
                payload: "x".to_string(),
            },
            attempts: 0,
            created_at_unix_ms: 1,
            next_retry_at_unix_ms: 1,
        };

        let mut first_pending = BTreeMap::new();
        first_pending.insert("ack-1".to_string(), mk_pending("ack-1"));
        let first = SessionState {
            session_id: "s1".to_string(),
            pending: first_pending,
        };
        assert!(store.try_upsert_session_with_ts(first, 1).is_ok());

        let mut second_pending = BTreeMap::new();
        second_pending.insert("ack-2".to_string(), mk_pending("ack-2"));
        let second = SessionState {
            session_id: "s2".to_string(),
            pending: second_pending,
        };
        let err = store
            .try_upsert_session_with_ts(second, 2)
            .expect_err("second pending item should hit clamped global quota");
        assert!(matches!(
            err,
            ReliabilityStoreError::CapacityExceeded { .. }
        ));
    }

    #[test]
    fn pending_total_quota_does_not_block_empty_session_touch_at_capacity() {
        let mut store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            max_pending_total: Some(1),
            ..InMemoryReliabilityStoreConfig::default()
        });

        let mut pending = BTreeMap::new();
        pending.insert(
            "ack-1".to_string(),
            PendingItem {
                ack_id: "ack-1".to_string(),
                message: ReliableMessage {
                    from: "alice".to_string(),
                    chain_id: "trnm-testnet".to_string(),
                    session_id: "s1".to_string(),
                    seq: Some(1),
                    nonce: None,
                    msg_type: "INPUT_CHUNK".to_string(),
                    payload: "x".to_string(),
                },
                attempts: 0,
                created_at_unix_ms: 1,
                next_retry_at_unix_ms: 1,
            },
        );

        assert!(store
            .try_upsert_session_with_ts(
                SessionState {
                    session_id: "s1".to_string(),
                    pending,
                },
                1,
            )
            .is_ok());

        assert!(store
            .try_upsert_session_with_ts(
                SessionState {
                    session_id: "s2".to_string(),
                    pending: BTreeMap::new(),
                },
                2,
            )
            .is_ok());
    }

    #[test]
    fn store_config_clamps_zero_empty_session_retention_window() {
        let store = InMemoryReliabilityStore::with_config(InMemoryReliabilityStoreConfig {
            empty_session_cleanup: EmptySessionCleanupPolicy::RetainForMs(0),
            ..InMemoryReliabilityStoreConfig::default()
        });

        assert!(matches!(
            store.config.empty_session_cleanup,
            EmptySessionCleanupPolicy::RetainForMs(1)
        ));
    }

    #[test]
    fn retry_config_is_sanitized_to_prevent_zero_delay_retry_spin() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 0,
                max_backoff_ms: 0,
                ..RetryConfig::default()
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, 1);
        assert_eq!(engine.retry.max_backoff_ms, 1);
    }

    #[test]
    fn collect_retry_cursor_wraps_safely_from_usize_max() {
        let store = InMemoryReliabilityStore::default();
        let mut engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                ..RetryConfig::default()
            },
        );

        engine.collect_rr_cursor = usize::MAX;
        let start = engine.advance_collect_rr_cursor(5);

        assert_eq!(start, usize::MAX % 5);
        assert_eq!(engine.collect_rr_cursor, 0);
    }

    #[test]
    fn retry_config_sanitizes_zero_attempt_and_circuit_thresholds() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 10,
                max_backoff_ms: 10,
                max_attempts: 0,
                circuit_breaker_threshold: 0,
                circuit_open_ms: 0,
            },
        );

        assert_eq!(engine.retry.max_attempts, 1);
        assert_eq!(engine.retry.circuit_breaker_threshold, 1);
        assert_eq!(engine.retry.circuit_open_ms, 10);
    }

    #[test]
    fn retry_config_sanitizes_zero_base_backoff_to_positive_floor() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 0,
                max_backoff_ms: 0,
                max_attempts: 1,
                circuit_breaker_threshold: 1,
                circuit_open_ms: 0,
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, 1);
        assert_eq!(engine.retry.max_backoff_ms, 1);
        assert_eq!(engine.retry.circuit_open_ms, 1);
    }

    #[test]
    fn retry_config_clamps_max_backoff_to_base_floor() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 25,
                max_backoff_ms: 5,
                ..RetryConfig::default()
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, 25);
        assert_eq!(engine.retry.max_backoff_ms, 25);
    }

    #[test]
    fn retry_config_clamps_circuit_open_window_to_base_floor() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(
            store,
            RetryConfig {
                base_backoff_ms: 50,
                max_backoff_ms: 100,
                circuit_open_ms: 10,
                ..RetryConfig::default()
            },
        );

        assert_eq!(engine.retry.base_backoff_ms, 50);
        assert_eq!(engine.retry.circuit_open_ms, 50);
    }

    #[test]
    fn retention_config_sanitizes_zero_cleanup_interval() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 1_000,
                pending_ttl_ms: 1_000,
                cleanup_interval_ms: 0,
            },
        );

        assert_eq!(engine.retention.cleanup_interval_ms, 1);
    }

    #[test]
    fn retention_config_sanitizes_zero_ttls_to_preserve_idempotency_and_retry_state() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new_with_retention(
            store,
            RetryConfig::default(),
            RetentionConfig {
                dedup_ttl_ms: 0,
                pending_ttl_ms: 0,
                cleanup_interval_ms: 1_000,
            },
        );

        assert_eq!(engine.retention.dedup_ttl_ms, 1);
        assert_eq!(engine.retention.pending_ttl_ms, 10_000);
        assert_eq!(engine.retention.cleanup_interval_ms, 1);
    }

    #[test]
    fn retry_exhausted_total_increment_saturates_at_u64_max() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(store, RetryConfig::default());

        engine
            .retry_exhausted_total
            .store(u64::MAX, Ordering::Relaxed);
        engine.increment_retry_exhausted_total();

        assert_eq!(engine.retry_exhausted_total(), u64::MAX);
    }

    #[test]
    fn circuit_counters_increment_saturates_at_u64_max() {
        let store = InMemoryReliabilityStore::default();
        let engine = ReliabilityEngine::new(store, RetryConfig::default());

        engine.circuit_open_total.store(u64::MAX, Ordering::Relaxed);
        ReliabilityEngine::<InMemoryReliabilityStore>::increment_atomic_saturating(
            &engine.circuit_open_total,
        );
        assert_eq!(engine.circuit_open_total(), u64::MAX);

        engine
            .circuit_recovered_total
            .store(u64::MAX, Ordering::Relaxed);
        ReliabilityEngine::<InMemoryReliabilityStore>::increment_atomic_saturating(
            &engine.circuit_recovered_total,
        );
        assert_eq!(engine.circuit_recovered_total(), u64::MAX);
    }
}
