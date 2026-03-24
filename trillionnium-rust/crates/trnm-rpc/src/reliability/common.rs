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

