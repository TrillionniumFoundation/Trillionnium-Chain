impl<S: ReliabilityStore> ReliabilityEngine<S> {
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

    !value.as_bytes().iter().any(|b| b.is_ascii_control())
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
