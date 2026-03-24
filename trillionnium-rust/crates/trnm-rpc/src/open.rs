use anyhow::Result;
use std::sync::atomic::Ordering;
use trnm_types::{RelaySession, RelaySessionStatus};

use crate::relay::state::{not_found, validate_session_id, RelayService, RelaySessionState};

#[derive(Debug, Clone)]
pub struct RelayOpenRequest {
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct RelayOpenResponse {
    pub session: RelaySession,
}

#[derive(Debug, Clone)]
pub struct RelayCloseRequest {
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct RelayCloseResponse {
    pub session: RelaySession,
}

impl RelayService {
    pub fn open(&self, req: RelayOpenRequest) -> Result<RelayOpenResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        self.relay_open_total.fetch_add(1, Ordering::Relaxed);
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("relay lock poisoned"))?;
        let state = g
            .entry(req.session_id.clone())
            .or_insert_with(|| RelaySessionState::new(req.session_id));
        if state.session.status == RelaySessionStatus::Closed {
            state.session.status = RelaySessionStatus::Open;
            state.session.closed_at_unix_ms = None;
        }
        Ok(RelayOpenResponse {
            session: state.session.clone(),
        })
    }

    pub fn close(&self, req: RelayCloseRequest) -> Result<RelayCloseResponse> {
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
        state.session.status = RelaySessionStatus::Closed;
        state.session.closed_at_unix_ms = Some(crate::relay::state::now_ms());

        Ok(RelayCloseResponse {
            session: state.session.clone(),
        })
    }
}
