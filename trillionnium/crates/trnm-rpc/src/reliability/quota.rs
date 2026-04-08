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

