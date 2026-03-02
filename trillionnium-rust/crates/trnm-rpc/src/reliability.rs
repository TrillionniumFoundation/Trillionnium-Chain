use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

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
        Self {
            sessions: HashMap::new(),
            dedup: HashMap::new(),
            meta: HashMap::new(),
            config,
        }
    }

    fn total_pending_items(&self) -> usize {
        self.sessions.values().map(|s| s.pending.len()).sum()
    }
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
        self.sessions.keys().cloned().collect()
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
            if !self.dedup.contains_key(&key) && self.dedup.len() >= max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("dedup limit reached ({max})"),
                });
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
        let old_len = self
            .sessions
            .get(&session_id)
            .map(|s| s.pending.len())
            .unwrap_or(0);
        let new_len = session.pending.len();
        let is_new_session = !self.sessions.contains_key(&session_id);

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
            let total = self.total_pending_items();
            let projected = total.saturating_sub(old_len).saturating_add(new_len);
            if projected > max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("pending total limit reached ({max})"),
                });
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
        self.dedup.retain(|_, seen_at| *seen_at >= dedup_cutoff);

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
                    meta.empty_since_unix_ms.get_or_insert(now_unix_ms);
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
}

impl<S: ReliabilityStore> ReliabilityEngine<S> {
    pub fn new(store: S, retry: RetryConfig) -> Self {
        Self::new_with_retention(store, retry, RetentionConfig::default())
    }

    pub fn new_with_retention(store: S, retry: RetryConfig, retention: RetentionConfig) -> Self {
        Self {
            store,
            retry,
            retention,
            last_cleanup_at_unix_ms: None,
            circuit_state: CircuitState::Closed,
            consecutive_retry_exhausted: 0,
        }
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_state
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
        if msg.chain_id.trim() != msg.chain_id
            || msg.from.trim() != msg.from
            || msg.session_id.trim() != msg.session_id
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
        if !msg.msg_type.is_empty()
            && (msg.msg_type.trim() != msg.msg_type
                || msg.msg_type != msg.msg_type.to_ascii_uppercase())
        {
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

        session.pending.insert(
            ack_id.clone(),
            PendingItem {
                ack_id: ack_id.clone(),
                message: msg,
                attempts: 0,
                created_at_unix_ms: now_unix_ms,
                next_retry_at_unix_ms: now_unix_ms + self.retry.base_backoff_ms as u128,
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
        let Some(mut session) = self.store.get_session(session_id) else {
            return false;
        };
        let removed = session.pending.remove(ack_id).is_some();
        if session.pending.is_empty() && self.store.should_remove_empty_session_immediately() {
            self.store.remove_session(session_id);
        } else if self.store.try_upsert_session_with_ts(session, 0).is_err() {
            return false;
        }
        removed
    }

    pub fn collect_due_retries(&mut self, now_unix_ms: u128) -> Vec<PendingItem> {
        self.maybe_cleanup(now_unix_ms);
        self.maybe_recover_circuit(now_unix_ms);

        if matches!(self.circuit_state, CircuitState::Open { .. }) {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut exhausted_in_this_round = 0u32;
        let session_ids = self.store.list_session_ids();

        for sid in session_ids {
            let Some(mut session) = self.store.get_session(&sid) else {
                continue;
            };

            session.pending.retain(|ack_id, item| {
                if item.next_retry_at_unix_ms > now_unix_ms {
                    return true;
                }

                if item.attempts >= self.retry.max_attempts {
                    exhausted_in_this_round = exhausted_in_this_round.saturating_add(1);
                    eprintln!(
                        "[reliability] drop pending after max_attempts ack_id={} attempts={}",
                        ack_id, item.attempts
                    );
                    // TODO(metrics): reliability_retry_exhausted_total += 1
                    return false;
                }

                item.attempts = item.attempts.saturating_add(1);
                let delay = exp_backoff_ms(
                    self.retry.base_backoff_ms,
                    self.retry.max_backoff_ms,
                    item.attempts,
                );
                item.next_retry_at_unix_ms = now_unix_ms + delay as u128;
                out.push(item.clone());
                true
            });

            if session.pending.is_empty() && self.store.should_remove_empty_session_immediately() {
                self.store.remove_session(&sid);
            } else {
                let _ = self.store.try_upsert_session_with_ts(session, now_unix_ms);
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
            let until_unix_ms = now_unix_ms + self.retry.circuit_open_ms as u128;
            self.circuit_state = CircuitState::Open { until_unix_ms };
            eprintln!(
                "[reliability] circuit open exhausted={} threshold={} until={}",
                self.consecutive_retry_exhausted,
                self.retry.circuit_breaker_threshold,
                until_unix_ms
            );
            // TODO(metrics): reliability_circuit_open_total += 1
        }
    }

    fn maybe_recover_circuit(&mut self, now_unix_ms: u128) {
        if let CircuitState::Open { until_unix_ms } = self.circuit_state {
            if now_unix_ms >= until_unix_ms {
                self.circuit_state = CircuitState::Closed;
                self.consecutive_retry_exhausted = 0;
                eprintln!("[reliability] circuit recovered at {}", now_unix_ms);
                // TODO(metrics): reliability_circuit_recovered_total += 1
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

fn exp_backoff_ms(base: u64, max: u64, attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(20);
    let factor = 1u64 << shift;
    base.saturating_mul(factor).min(max)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityStoreMode {
    Sqlite,
    Memory,
}

impl ReliabilityStoreMode {
    pub fn from_env() -> Self {
        match std::env::var("RELIABILITY_STORE")
            .unwrap_or_else(|_| "sqlite".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
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
}

impl SqliteReliabilityStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ReliabilityStoreError> {
        let conn = Connection::open(path).map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("open sqlite failed: {e}"),
        })?;
        Self::configure_connection(&conn)?;
        Self::apply_migrations(&conn)?;
        Ok(Self { conn })
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
                   updated_at_unix_ms=excluded.updated_at_unix_ms",
                rusqlite::params![session.session_id, payload, ts],
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("upsert session failed: {e}"),
            })?;
        Ok(())
    }

    fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let cutoff = now_unix_ms.saturating_sub(retention.dedup_ttl_ms as u128);
        let cutoff_i64 = i64::try_from(cutoff).unwrap_or(i64::MAX);
        let _ = self.conn.execute(
            "DELETE FROM reliability_dedup WHERE seen_at_unix_ms < ?1",
            [cutoff_i64],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let after_ttl = engine.receive(mk_msg("alice", "s1", 9), 1_101);
        assert_eq!(after_ttl.code, AckCode::Accepted);
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
        assert!(engine.mark_acked("s1", &ack.ack_id));

        // Empty session should still exist before its empty-session ttl elapses.
        let due = engine.collect_due_retries(1_100);
        assert!(due.is_empty());

        let store = engine.into_store();
        assert!(store.get_session("s1").is_some());
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
}
