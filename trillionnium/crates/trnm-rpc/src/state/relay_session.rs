use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use trnm_types::{RelayEnvelope, RelaySession, RelaySessionStatus};

use crate::relay::route::RelayRouter;

use super::{
    bad_request, canonicalize_risk_source, now_ms, validate_session_id, RiskDomain,
    RiskQuotaConfig, RiskQuotaState,
};

pub(crate) const MAX_RELAY_QUERY_LIMIT: usize = 1_000;
pub(crate) const MAX_PROOF_QUERY_SPAN: u64 = 10_000;

pub(crate) fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub(crate) fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub(crate) fn hash_envelope(env: &RelayEnvelope) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(env)?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn merkle_root_and_proofs(
    leaves: &[[u8; 32]],
) -> ([u8; 32], Vec<Vec<crate::relay::dispatch::RelayProofStep>>) {
    if leaves.is_empty() {
        return (hash_bytes(&[]), vec![]);
    }

    let mut proofs: Vec<Vec<crate::relay::dispatch::RelayProofStep>> =
        vec![Vec::new(); leaves.len()];
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut indexes: Vec<Vec<usize>> = (0..leaves.len()).map(|i| vec![i]).collect();

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut next_indexes = Vec::with_capacity(indexes.len().div_ceil(2));

        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };

            for &leaf_idx in &indexes[i] {
                proofs[leaf_idx].push(crate::relay::dispatch::RelayProofStep {
                    sibling_hash_hex: hex::encode(right),
                    sibling_is_left: false,
                });
            }
            if i + 1 < level.len() {
                for &leaf_idx in &indexes[i + 1] {
                    proofs[leaf_idx].push(crate::relay::dispatch::RelayProofStep {
                        sibling_hash_hex: hex::encode(left),
                        sibling_is_left: true,
                    });
                }
            }

            next_level.push(hash_pair(&left, &right));
            let mut merged = indexes[i].clone();
            if i + 1 < indexes.len() {
                merged.extend(indexes[i + 1].iter().copied());
            }
            next_indexes.push(merged);
            i += 2;
        }

        level = next_level;
        indexes = next_indexes;
    }

    (level[0], proofs)
}

#[derive(Debug)]
pub(crate) struct RelaySessionState {
    pub(crate) session: RelaySession,
    pub(crate) next_sequence: u64,
    pub(crate) queue: VecDeque<RelayEnvelope>,
    pub(crate) envelope_hashes: Vec<[u8; 32]>,
    pub(crate) acked_ids: BTreeSet<u64>,
    pub(crate) poll_start_idx: usize,
}

impl RelaySessionState {
    pub(crate) fn new(session_id: String) -> Self {
        Self {
            session: RelaySession {
                session_id,
                status: RelaySessionStatus::Open,
                created_at_unix_ms: now_ms(),
                closed_at_unix_ms: None,
            },
            next_sequence: 1,
            queue: VecDeque::new(),
            envelope_hashes: Vec::new(),
            acked_ids: BTreeSet::new(),
            poll_start_idx: 0,
        }
    }

    pub(crate) fn ensure_open(&self) -> Result<()> {
        if self.session.status == RelaySessionStatus::Closed {
            return Err(bad_request(
                "session_closed",
                format!("relay session closed: {}", self.session.session_id),
            ));
        }
        Ok(())
    }

    pub(crate) fn append_envelope(&mut self, envelope: RelayEnvelope) -> Result<()> {
        let hash = hash_envelope(&envelope)?;
        self.queue.push_back(envelope);
        self.envelope_hashes.push(hash);
        Ok(())
    }

    pub(crate) fn advance_poll_start_idx(&mut self) {
        while let Some(env) = self.queue.get(self.poll_start_idx) {
            if self.acked_ids.contains(&env.envelope_id) {
                self.poll_start_idx += 1;
            } else {
                break;
            }
        }
    }
}

pub struct RelayService {
    pub(crate) sessions: Mutex<HashMap<String, RelaySessionState>>,
    pub(crate) router: RelayRouter,
    pub(crate) envelope_id: AtomicU64,
    pub(crate) risk_quota: Mutex<RiskQuotaState>,
    pub(crate) risk_quota_cfg: RiskQuotaConfig,
    pub(crate) relay_open_total: AtomicU64,
    pub(crate) relay_poll_total: AtomicU64,
    pub(crate) relay_send_rejected_route_not_registered_total: AtomicU64,
    pub(crate) proof_query_rejected_range_out_of_bounds_total: AtomicU64,
}

impl RelayService {
    pub fn new(router: RelayRouter) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            router,
            envelope_id: AtomicU64::new(1),
            risk_quota: Mutex::new(RiskQuotaState::default()),
            risk_quota_cfg: RiskQuotaConfig::default(),
            relay_open_total: AtomicU64::new(0),
            relay_poll_total: AtomicU64::new(0),
            relay_send_rejected_route_not_registered_total: AtomicU64::new(0),
            proof_query_rejected_range_out_of_bounds_total: AtomicU64::new(0),
        }
    }

    pub fn with_risk_quota_config(router: RelayRouter, risk_quota_cfg: RiskQuotaConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            router,
            envelope_id: AtomicU64::new(1),
            risk_quota: Mutex::new(RiskQuotaState::default()),
            risk_quota_cfg,
            relay_open_total: AtomicU64::new(0),
            relay_poll_total: AtomicU64::new(0),
            relay_send_rejected_route_not_registered_total: AtomicU64::new(0),
            proof_query_rejected_range_out_of_bounds_total: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn relay_open_total(&self) -> u64 {
        self.relay_open_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn relay_poll_total(&self) -> u64 {
        self.relay_poll_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn relay_send_rejected_route_not_registered_total(&self) -> u64 {
        self.relay_send_rejected_route_not_registered_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn proof_query_rejected_range_out_of_bounds_total(&self) -> u64 {
        self.proof_query_rejected_range_out_of_bounds_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn consume_risk_quota(
        &self,
        domain: RiskDomain,
        session_id: &str,
        source: Option<&str>,
    ) -> Result<()> {
        let source = canonicalize_risk_source(source);
        let mut q = match self.risk_quota.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        q.consume(
            now_ms(),
            domain,
            session_id,
            source.as_str(),
            &self.risk_quota_cfg,
        )
    }

    pub fn check_challenge_quota(&self, session_id: &str, source: Option<&str>) -> Result<()> {
        validate_session_id(session_id, "session_id")?;
        self.consume_risk_quota(RiskDomain::Challenge, session_id, source)
    }
}
