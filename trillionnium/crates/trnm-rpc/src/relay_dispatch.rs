use super::*;

impl RelayService {
    pub fn send(&self, req: RelaySendRequest) -> Result<RelaySendResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        validate_route(&req.route)?;
        self.consume_risk_quota(RiskDomain::Relay, &req.session_id, req.source.as_deref())?;
        if !self.router.has_route(&req.route) {
            self.relay_send_rejected_route_not_registered_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(bad_request(
                "invalid_route",
                format!("route not registered: {}", req.route),
            ));
        }

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
        state.ensure_open()?;

        let envelope = RelayEnvelope {
            envelope_id: self.envelope_id.fetch_add(1, Ordering::Relaxed),
            session_id: req.session_id.clone(),
            sequence: state.next_sequence,
            route: req.route,
            from: req.from,
            to: req.to,
            payload: req.payload,
            created_at_unix_ms: now_ms(),
        };
        state.next_sequence += 1;
        state.append_envelope(envelope.clone())?;

        for mut routed in self.router.dispatch(&envelope)? {
            routed.session_id = envelope.session_id.clone();
            routed.sequence = state.next_sequence;
            if routed.envelope_id == 0 {
                routed.envelope_id = self.envelope_id.fetch_add(1, Ordering::Relaxed);
            }
            if routed.created_at_unix_ms == 0 {
                routed.created_at_unix_ms = now_ms();
            }
            state.next_sequence += 1;
            state.append_envelope(routed)?;
        }

        Ok(RelaySendResponse { envelope })
    }

    pub fn poll(&self, req: RelayPollRequest) -> Result<RelayPollResponse> {
        validate_session_id(&req.session_id, "session_id")?;
        let g = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("relay lock poisoned"))?;
        let Some(state) = g.get(&req.session_id) else {
            return Err(not_found(
                "session_not_found",
                format!("relay session not found: {}", req.session_id),
            ));
        };

        let limit = req.limit.clamp(1, MAX_RELAY_QUERY_LIMIT);
        self.relay_poll_total.fetch_add(1, Ordering::Relaxed);
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
}
