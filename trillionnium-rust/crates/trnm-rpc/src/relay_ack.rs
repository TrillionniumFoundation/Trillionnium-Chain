use super::*;

impl RelayService {
    pub fn ack(&self, req: RelayAckRequest) -> Result<RelayAckResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        let mut g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get_mut(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let before = state.acked_ids.len();

        if !req.envelope_ids.is_empty() {
            let known_ids: HashSet<u64> = state.queue.iter().map(|e| e.envelope_id).collect();
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
