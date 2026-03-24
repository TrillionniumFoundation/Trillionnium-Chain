use anyhow::Result;

use crate::relay::state::{not_found, validate_session_id, RelayService, MAX_RELAY_QUERY_LIMIT};
use trnm_types::RelayEnvelope;

#[derive(Debug, Clone)]
pub struct RelayPollRequest {
    pub session_id: String,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct RelayPollResponse {
    pub session_id: String,
    pub envelopes: Vec<RelayEnvelope>,
}

#[derive(Debug, Clone)]
pub struct RelayAckRequest {
    pub session_id: String,
    /// Backward-compatible single/batch ack by envelope id.
    pub envelope_ids: Vec<u64>,
    /// Batch ack by sequence upper-bound (inclusive) within the session.
    pub upto_seq: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RelayAckResponse {
    pub session_id: String,
    pub acked: usize,
}

impl RelayService {
    pub fn poll(&self, req: RelayPollRequest) -> Result<RelayPollResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        let g = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let limit = req.limit.clamp(1, MAX_RELAY_QUERY_LIMIT);
        self.relay_poll_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let envelopes = state
            .queue
            .iter()
            .skip(state.poll_start_idx)
            .filter(|e| !state.acked_ids.contains(&e.envelope_id))
            .take(limit)
            .cloned()
            .collect();
        Ok(RelayPollResponse {
            session_id: req.session_id,
            envelopes,
        })
    }

    pub fn ack(&self, req: RelayAckRequest) -> Result<RelayAckResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let before = state.acked_ids.len();

        if !req.envelope_ids.is_empty() {
            let known_ids: std::collections::HashSet<u64> =
                state.queue.iter().map(|e| e.envelope_id).collect();
            for id in req.envelope_ids {
                if known_ids.contains(&id) {
                    state.acked_ids.insert(id);
                }
            }
        }

        if let Some(upto_seq) = req.upto_seq {
            for env in &state.queue {
                if env.sequence <= upto_seq {
                    state.acked_ids.insert(env.envelope_id);
                }
            }
        }

        state.advance_poll_start_idx();

        Ok(RelayAckResponse {
            session_id: req.session_id,
            acked: state.acked_ids.len().saturating_sub(before),
        })
    }
}
